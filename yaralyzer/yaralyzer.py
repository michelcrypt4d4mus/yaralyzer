"""
Central class that handles setting up / compiling rules and reading binary data from files as needed.
Alternate constructors are provided depending on whether:
    1. YARA rules are already compiled
    2. YARA rules should be compiled from a string
    3. YARA rules should be read from a file
    4. YARA rules should be read from a directory of .yara files
"""
from collections import defaultdict
from os import listdir, path
from typing import Iterator, List, Optional, Tuple, Union

import yara
from rich.padding import Padding
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.config import YARALYZE, YaralyzerConfig
from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.helpers.file_helper import load_binary_data
from yaralyzer.helpers.rich_text_helper import dim_if, reverse_color
from yaralyzer.helpers.string_helper import comma_join, newline_join
from yaralyzer.output.rich_console import YARALYZER_THEME, console
from yaralyzer.output.regex_match_metrics import RegexMatchMetrics
from yaralyzer.util.logging import log
from yaralyzer.yara.yara_match import YaraMatch
from yaralyzer.yara.yara_rule_builder import yara_rule_string

YARA_EXT = '.yara'


class Yaralyzer:
    # TODO: might be worth introducing a Scannable namedtuple or similar
    def __init__(
            self,
            rules: Union[str, yara.Rules],
            rules_label: str,
            scannable: Union[bytes, str],
            bytes_label: Optional[str] = None,
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> None:
        """
        If rules is a string it will be compiled by yara
        If scannable is bytes then bytes_label must be provided.
        If scannable is a string it is assumed to be a file that bytes should be read from
        and the bytes_label will be set to the file's basename.
        """
        if isinstance(scannable, bytes):
            if bytes_label is None:
                raise TypeError("Must provide bytes_label arg when yaralyzing raw bytes")

            self.bytes: bytes = scannable
            self.bytes_label: str = bytes_label
        else:
            self.bytes: bytes = load_binary_data(scannable)
            self.bytes_label: str = bytes_label or path.basename(scannable)

        self.bytes_length: int = len(self.bytes)
        self.rules: yara.Rules = rules if isinstance(rules, yara.Rules) else yara.compile(source=rules)
        self.rules_label: str = rules_label
        self.highlight_style: str = highlight_style
        # Outcome racking variables
        self.suppression_notice_queue: list = []
        self.matches: List[YaraMatch] = []
        self.non_matches: List[dict] = []
        self.regex_extraction_stats: defaultdict = defaultdict(lambda: RegexMatchMetrics())

    @classmethod
    def for_rules_files(
            cls,
            yara_rules_files: List[str],
            scannable: Union[bytes, str],
            bytes_label: Optional[str] = None
        ) -> 'Yaralyzer':
        """Alternate constructor loads yara rules from files, labels rules w/filenames"""
        if not isinstance(yara_rules_files, list):
            raise TypeError(f"{yara_rules_files} is not a list")

        filepaths_arg = {path.basename(file): file for file in yara_rules_files}
        yara_rules = yara.compile(filepaths=filepaths_arg)
        yara_rules_label = comma_join(yara_rules_files, func=path.basename)
        return cls(yara_rules, yara_rules_label, scannable, bytes_label)

    @classmethod
    def for_rules_dirs(
            cls,
            dirs: List[str],
            scannable: Union[bytes, str],
            bytes_label: Optional[str] = None
        ) -> 'Yaralyzer':
        """Alternate constructor that will load all .yara files in yara_rules_dir"""
        if not isinstance(dirs, list):
            raise TypeError(f"'{dirs}' is not a list of directories")

        rules_files = [
            path.join(dir, f)
            for dir in dirs
            for f in listdir(dir)
            if f.endswith(YARA_EXT)
        ]

        return cls.for_rules_files(rules_files, scannable, bytes_label)

    @classmethod
    def for_patterns(
            cls,
            patterns: List[str],
            scannable: Union[bytes, str],
            bytes_label: Optional[str] = None,
            pattern_label: Optional[str] = None,  # TODO: actually use the pattern label in the generated rule
            regex_modifier: Optional[str] = None
        ) -> 'Yaralyzer':
        """Constructor taking regex pattern strings. Rules label defaults to patterns joined by comma"""
        rule_strings = [
            yara_rule_string(pattern, f"{YARALYZE}_{i + 1}", modifier=regex_modifier)
            for i, pattern in enumerate(patterns)
        ]

        rules_string = newline_join(rule_strings)
        rules_label = comma_join(patterns)
        return cls(rules_string, rules_label, scannable, bytes_label)

    def yaralyze(self) -> None:
        """Use YARA to find matches and then force decode them"""
        for bytes_match, bytes_decoder in self.match_iterator():
            log.debug(bytes_match)

    def match_iterator(self) -> Iterator[Tuple[BytesMatch, BytesDecoder]]:
        """Iterator version of yaralyze. Yields match and decode data tuple back to caller."""
        self.rules.match(data=self.bytes, callback=self._yara_callback)

        for yara_match in self.matches:
            console.print(yara_match, Text("\n"))

            for match in BytesMatch.from_yara_match(self.bytes, yara_match.match, self.highlight_style):
                decoder = BytesDecoder(match, yara_match.rule_name)
                decoder.print_decode_attempts()
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
            console.print(dim_if(self.__rich__()  + Text(non_match_desc, style='grey.dark'), True))
            return

        non_match_desc = f" did not match the other {len(self.non_matches)} yara rules"
        console.print(self.__rich__() + Text(non_match_desc, style='grey') + Text(': '), style='dim')
        console.print(Padding(Text(', ', 'white').join(non_matches_text), (0, 0, 1, 4)))

    def _panel_text(self) -> Text:
        """Inverted colors for the panel at the top of the match section of the output"""
        styles = [reverse_color(YARALYZER_THEME.styles[f"yara.{s}"]) for s in ('scanned', 'rules')]
        return self._text_rep(*styles)

    def _text_rep(self, byte_style: str = 'yara.scanned', rule_style: str = 'yara.rules') -> Text:
        """Text representation of this YARA scan"""
        txt = Text('').append(self.bytes_label, style=byte_style or 'yara.scanned')
        return txt.append(' scanned with <').append(self.rules_label, style=rule_style or 'yara.rules').append('>')

    def _filename_string(self):
        """The string to use when exporting this yaralyzer to SVG?HTML/etc"""
        return str(self).replace('>', '').replace('<', '').replace(' ', '_')

    def __rich__(self) -> Text:
        return self._text_rep()

    def __str__(self) -> str:
        return self.__rich__().plain
