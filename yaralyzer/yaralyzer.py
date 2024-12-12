"""
Central class that handles setting up / compiling rules and reading binary data from files as needed.
Alternate constructors are provided depending on whether:
    1. YARA rules are already compiled
    2. YARA rules should be compiled from a string
    3. YARA rules should be read from a file
    4. YARA rules should be read from a directory of .yara files

The real action happens in the __rich__console__() dunder method.
"""
from os import path
from sys import exit
from typing import Iterator, List, Optional, Tuple, Union

import yara
from rich.console import Console, ConsoleOptions, RenderResult
from rich.padding import Padding
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.config import YARALYZE, YaralyzerConfig
from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.helpers.file_helper import files_in_dir, load_binary_data
from yaralyzer.helpers.rich_text_helper import dim_if, reverse_color
from yaralyzer.helpers.string_helper import comma_join, newline_join
from yaralyzer.output.regex_match_metrics import RegexMatchMetrics
from yaralyzer.output.rich_console import YARALYZER_THEME, console, print_fatal_error_and_exit
from yaralyzer.output.file_hashes_table import bytes_hashes_table
from yaralyzer.util.logging import log
from yaralyzer.yara.yara_match import YaraMatch
from yaralyzer.yara.yara_rule_builder import yara_rule_string

YARA_FILE_DOES_NOT_EXIST_ERROR_MSG = "is not a valid yara rules file (it doesn't exist)"


# TODO: might be worth introducing a Scannable namedtuple or similar
class Yaralyzer:
    def __init__(
            self,
            rules: Union[str, yara.Rules],
            rules_label: str,
            scannable: Union[bytes, str],
            scannable_label: Optional[str] = None,
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> None:
        """
        If rules is a string it will be compiled by yara
        If scannable is bytes then scannable_label must be provided.
        If scannable is a string it is assumed to be a file that bytes should be read from
        and the scannable_label will be set to the file's basename.
        """
        if 'args' not in vars(YaralyzerConfig):
            YaralyzerConfig.set_default_args()

        yara.set_config(
            stack_size=YaralyzerConfig.args.yara_stack_size,
            max_match_data=YaralyzerConfig.args.max_match_length
        )

        if isinstance(scannable, bytes):
            if scannable_label is None:
                raise TypeError("Must provide scannable_label arg when yaralyzing raw bytes")

            self.bytes: bytes = scannable
            self.scannable_label: str = scannable_label
        else:
            self.bytes: bytes = load_binary_data(scannable)
            self.scannable_label: str = scannable_label or path.basename(scannable)

        if isinstance(rules, yara.Rules):
            self.rules: yara.Rules = rules
        else:
            log.info(f"Compiling YARA rules from provided string:\n{rules}")
            self.rules: yara.Rules = yara.compile(source=rules)

        self.bytes_length: int = len(self.bytes)
        self.rules_label: str = rules_label
        self.highlight_style: str = highlight_style
        # Outcome tracking variables
        self.non_matches: List[dict] = []
        self.matches: List[YaraMatch] = []
        self.extraction_stats = RegexMatchMetrics()

    @classmethod
    def for_rules_files(
            cls,
            yara_rules_files: List[str],
            scannable: Union[bytes, str],
            scannable_label: Optional[str] = None
        ) -> 'Yaralyzer':
        """Alternate constructor loads yara rules from files, labels rules w/filenames"""
        if not isinstance(yara_rules_files, list):
            raise TypeError(f"{yara_rules_files} is not a list")

        for file in yara_rules_files:
            if not path.exists(file):
                raise ValueError(f"'{file}' {YARA_FILE_DOES_NOT_EXIST_ERROR_MSG}")

        filepaths_arg = {path.basename(file): file for file in yara_rules_files}

        try:
            yara_rules = yara.compile(filepaths=filepaths_arg)
        except yara.SyntaxError as e:
            print_fatal_error_and_exit(f"Failed to parse YARA rules file(s): {e}")

        yara_rules_label = comma_join(yara_rules_files, func=path.basename)
        return cls(yara_rules, yara_rules_label, scannable, scannable_label)

    @classmethod
    def for_rules_dirs(
            cls,
            dirs: List[str],
            scannable: Union[bytes, str],
            scannable_label: Optional[str] = None
        ) -> 'Yaralyzer':
        """Alternate constructor that will load all .yara files in yara_rules_dir"""
        if not (isinstance(dirs, list) and all(path.isdir(dir) for dir in dirs)):
            raise TypeError(f"'{dirs}' is not a list of valid directories")

        rules_files = [path.join(dir, f) for dir in dirs for f in files_in_dir(dir)]
        return cls.for_rules_files(rules_files, scannable, scannable_label)

    @classmethod
    def for_patterns(
            cls,
            patterns: List[str],
            patterns_type: str,
            scannable: Union[bytes, str],
            scannable_label: Optional[str] = None,
            rules_label: Optional[str] = None,
            pattern_label: Optional[str] = None,
            regex_modifier: Optional[str] = None,
        ) -> 'Yaralyzer':
        """Constructor taking regex pattern strings. Rules label defaults to patterns joined by comma"""
        rule_strings = []

        for i, pattern in enumerate(patterns):
            suffix = f"_{i + 1}" if len(patterns) > 1 else ''

            rule_strings.append(yara_rule_string(
                pattern=pattern,
                pattern_type=patterns_type,
                rule_name=f"{rules_label or YARALYZE}{suffix}",
                pattern_label=f"{pattern_label}{suffix}" if pattern_label else None,
                modifier=regex_modifier
            ))

        rules_string = newline_join(rule_strings)
        rules_label = comma_join(patterns)
        return cls(rules_string, rules_label, scannable, scannable_label)

    def yaralyze(self) -> None:
        """Use YARA to find matches and then force decode them"""
        console.print(self)

    def match_iterator(self) -> Iterator[Tuple[BytesMatch, BytesDecoder]]:
        """Iterator version of yaralyze. Yields match and decode data tuple back to caller."""
        self.rules.match(data=self.bytes, callback=self._yara_callback)

        for yara_match in self.matches:
            console.print(yara_match)
            console.line()

            for match in BytesMatch.from_yara_match(self.bytes, yara_match.match, self.highlight_style):
                decoder = BytesDecoder(match, yara_match.rule_name)
                self.extraction_stats.tally_match(decoder)
                yield match, decoder

        self._print_non_matches()

    def _yara_callback(self, data: dict):
        if data['matches']:
            self.matches.append(YaraMatch(data, self._panel_text()))
        else:
            self.non_matches.append(data)

        return yara.CALLBACK_CONTINUE

    def _print_non_matches(self) -> None:
        """Print info about the YARA rules that didn't match the bytes"""
        if len(self.non_matches) == 0:
            return

        non_matches_text = sorted([Text(nm['rule'], 'grey') for nm in self.non_matches], key=str)

        # Only show the non matches if there were valid ones, otherwise just show the number
        if len(self.matches) == 0:
            non_match_desc = f" did not match any of the {len(self.non_matches)} yara rules"
            console.print(dim_if(self.__text__()  + Text(non_match_desc, style='grey'), True))
            return

        non_match_desc = f" did not match the other {len(self.non_matches)} yara rules"
        console.print(self.__text__() + Text(non_match_desc, style='grey') + Text(': '), style='dim')
        console.print(Padding(Text(', ', 'white').join(non_matches_text), (0, 0, 1, 4)))

    def _panel_text(self) -> Text:
        """Inverted colors for the panel at the top of the match section of the output"""
        styles = [reverse_color(YARALYZER_THEME.styles[f"yara.{s}"]) for s in ('scanned', 'rules')]
        return self.__text__(*styles)

    def _filename_string(self):
        """The string to use when exporting this yaralyzer to SVG/HTML/etc"""
        return str(self).replace('>', '').replace('<', '').replace(' ', '_')

    def __text__(self, byte_style: str = 'yara.scanned', rule_style: str = 'yara.rules') -> Text:
        """Text representation of this YARA scan (__text__() was taken)"""
        txt = Text('').append(self.scannable_label, style=byte_style or 'yara.scanned')
        return txt.append(' scanned with <').append(self.rules_label, style=rule_style or 'yara.rules').append('>')

    def __rich_console__(self, _console: Console, options: ConsoleOptions) -> RenderResult:
        """Does the stuff. TODO: not the best place to put the core logic"""
        yield bytes_hashes_table(self.bytes, self.scannable_label)

        for _bytes_match, bytes_decoder in self.match_iterator():
            for attempt in bytes_decoder.__rich_console__(_console, options):
                yield attempt

    def __str__(self) -> str:
        return self.__text__().plain
