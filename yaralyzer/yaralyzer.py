"""Main Yaralyzer class and alternate constructors."""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

import yara
from rich.console import Console, ConsoleOptions, RenderResult
from rich.padding import Padding
from rich.style import Style
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.config import YaralyzerConfig
from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.output.console import console
from yaralyzer.output.file_hashes_table import bytes_hashes_table
from yaralyzer.output.regex_match_metrics import RegexMatchMetrics
from yaralyzer.output.theme import BYTES_BRIGHTER, YARALYZER_THEME
from yaralyzer.util.constants import MAX_FILENAME_LENGTH, YARALYZE
from yaralyzer.util.exceptions import print_fatal_error_and_exit
from yaralyzer.util.helpers.file_helper import files_in_dir, to_paths
from yaralyzer.util.helpers.rich_helper import dim_if, reverse_color
from yaralyzer.util.helpers.string_helper import comma_join, newline_join
from yaralyzer.util.logging import log
from yaralyzer.yara.yara_match import YaraMatch
from yaralyzer.yara.yara_rule_builder import PatternType, YaraModifierType, yara_rule_string

YARA_FILE_DOES_NOT_EXIST_ERROR_MSG = "is not a valid yara rules file (it doesn't exist)"
INVALID_FOR_FILENAME_REGEX = re.compile(r"[^\w,.=+-;]+")


@dataclass
class Yaralyzer:
    """
    Central class that handles setting up / compiling YARA rules and reading binary data from files as needed.

    Alternate constructors are provided depending on whether:

    * YARA rules are already compiled

    * YARA rules should be compiled from a string

    * YARA rules should be read from a file

    * YARA rules should be read from a directory of .yara files

    The real action happens in the `__rich__console__()` dunder method.

    Attributes:
        rules (yara.Rules): The YARA rules to use for scanning.
        rules_label (str): A label for the ruleset, typically derived from filenames or user input.
        scannable (bytes | str | Path): The data to scan. If it's `bytes` then that data is scanned;
            if it's a string it is treated as a file path to load bytes from.
        scannable_label (str, optional): A label for the binary data. Required if `scannable` is raw
            `bytes`, otherwise defaults to the basename of `scannable` file.
        highlight_style (str, optional): The style to use for highlighting matches in the output.
        _bytes (bytes): The binary data to scan, derived from the `scannable` arg.
        non_matches (list[dict]): A list of YARA rules that did not match the binary data.
        matches (list[YaraMatch]): A list of YaraMatch objects representing the matches found.
        extraction_stats (RegexMatchMetrics): Metrics related to decoding attempts on matched data

    Raises:
        TypeError: If `scannable` is `bytes` and `scannable_label` is not provided.
    """
    rules: yara.Rules
    rules_label: str
    scannable: str | bytes | Path
    scannable_label: str = ''
    highlight_style: str = BYTES_BRIGHTER
    _bytes: bytes = field(init=False)

    # Outcome tracking variables
    non_matches: list[dict] = field(default_factory=list)
    matches: list[YaraMatch] = field(default_factory=list)
    extraction_stats: RegexMatchMetrics = field(default_factory=RegexMatchMetrics)

    def __post_init__(self):
        yara.set_config(
            stack_size=YaralyzerConfig.args.yara_stack_size,
            max_match_data=YaralyzerConfig.args.max_match_length
        )

        if isinstance(self.scannable, (bytes, bytearray, memoryview)):
            if not self.scannable_label:
                raise TypeError("Must provide 'scannable_label' arg when yaralyzing raw bytes")

            self._bytes = self.scannable
        else:
            self.scannable = Path(self.scannable)
            self._bytes = self.scannable.read_bytes()
            self.scannable_label = self.scannable_label or self.scannable.name

    @classmethod
    def for_rules_files(
        cls,
        yara_rules_files: list[str] | list[Path],
        scannable: bytes | str | Path,
        scannable_label: str = ''
    ) -> 'Yaralyzer':
        """
        Alternate constructor to load YARA rules from files and label rules with the filenames.

        Args:
            yara_rules_files (list[str]): list of file paths to YARA rules files.
            scannable (Union[bytes, str]): The data to scan. If `bytes`, raw data is scanned;
                if `str`, it is treated as a file path to load bytes from.
            scannable_label (str, optional): Label for the `scannable` data.
                Required if `scannable` is `bytes`. If scannable is a file path, defaults to the file's basename.

        Raises:
            FileNotFoundError: If any file in `yara_rules_files` does not exist.
            TypeError: If `yara_rules_files` is not a list of Paths or strings
        """
        yara_rules_paths = to_paths(yara_rules_files)

        for rules_path in yara_rules_paths:
            if not rules_path.exists():
                raise FileNotFoundError(f"'{rules_path}' {YARA_FILE_DOES_NOT_EXIST_ERROR_MSG}")

        try:
            filepaths_arg = {f.name: str(f) for f in yara_rules_paths}
            yara_rules = yara.compile(filepaths=filepaths_arg)
        except yara.SyntaxError as e:
            print_fatal_error_and_exit(f"Failed to parse YARA rules file(s): {e}")

        yara_rules_label = comma_join(sorted([file.name for file in yara_rules_paths]))
        return cls(yara_rules, yara_rules_label, scannable, scannable_label)

    @classmethod
    def for_rules_dirs(
        cls,
        dirs: list[str] | list[Path] | list[str | Path],
        scannable: bytes | str | Path,
        scannable_label: str = ''
    ) -> 'Yaralyzer':
        """
        Alternate constructor that will load all `.yara` files in `yara_rules_dir`.

        Args:
            dirs (list[str]): list of directories to search for `.yara` files.
            scannable (Union[bytes, str]): The data to scan. If `bytes`, raw data is scanned;
                if `str`, it is treated as a file path to load bytes from.
            scannable_label (str | None, optional): Label for the `scannable` data.
                Required if `scannable` is `bytes`. If scannable is a file path, defaults to the file's basename.

        Raises:
            FileNotFoundError: If `dirs` is not a list of valid directories.
        """
        dirs = to_paths(dirs)

        if not all(dir.is_dir() and dir.exists() for dir in dirs):
            raise FileNotFoundError(f"'{dirs}' is not a list of valid directories")

        rules_files = [f for dir in dirs for f in files_in_dir(dir)]
        log.info(f"Found {len(rules_files)} in {len(dirs)} dirs: {rules_files}")
        return cls.for_rules_files(rules_files, scannable, scannable_label)

    @classmethod
    def for_patterns(
        cls,
        patterns: list[str],
        patterns_type: PatternType,
        scannable: bytes | str | Path,
        scannable_label: str = '',
        rules_label: str | None = None,
        pattern_label: str | None = None,
        regex_modifier: YaraModifierType | None = None,
    ) -> 'Yaralyzer':
        """
        Alternate constructor taking regex pattern strings. Rules label defaults to the patterns joined by comma.

        Args:
            patterns (list[str]): list of regex or hex patterns to build rules from.
            patterns_type (PatternType): Either `"regex"` or `"hex"` to indicate the type of patterns provided.
            scannable (Union[bytes, str]): The data to scan. If `bytes`, raw data is scanned;
                if `str`, it is treated as a file path to load bytes from.
            scannable_label (str | None, optional): Label for the `scannable` data. Required if `scannable` is `bytes`.
                If scannable is a file path, defaults to the file's basename.
            rules_label (str | None, optional): Label for the ruleset. Defaults to the patterns joined by comma.
            pattern_label (str | None, optional): Label for each pattern in the YARA rules. Defaults to "pattern".
            regex_modifier (str | None, optional): Optional regex modifier (e.g. "nocase", "ascii", "wide", etc).
                Only valid if `patterns_type` is `"regex"`.
        """
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

        rules_label = comma_join(patterns)
        rules_string = newline_join(rule_strings)
        log.info(f"Compiling YARA rules from rules_string:\n{rules_string}")
        rules = yara.compile(source=rules_string)
        return cls(rules, rules_label, scannable, scannable_label)

    def export_basepath(self) -> Path:
        """Get the basepath (directory + filename without extension) for exported files."""
        args = YaralyzerConfig.args
        filename_str = INVALID_FOR_FILENAME_REGEX.sub('', str(self).replace(', ', ',').replace(' ', '_'))
        export_basename  = f"{args.file_prefix}{filename_str}"  # noqa: E221
        export_basename += f"__maxdecode{YaralyzerConfig.args.max_decode_length}"
        export_basename += args.file_suffix

        if not args.no_timestamps:
            export_basename += f"__at_{args._invoked_at_str}"

        max_filename_length = MAX_FILENAME_LENGTH - len(str(args.output_dir.resolve()))
        return args.output_dir.joinpath(export_basename[:max_filename_length])

    def yaralyze(self) -> None:
        """Use YARA to find matches and then force decode them."""
        console.print(self)

    def match_iterator(self) -> Iterator[tuple[BytesMatch, BytesDecoder]]:
        """
        Iterator version of `yaralyze()`.

        Yields:
            tuple[BytesMatch, BytesDecoder]: Match and decode data tuple.
        """
        self.rules.match(data=self._bytes, callback=self._yara_callback)

        for yara_match in self.matches:
            console.print(yara_match)
            console.line()

            for match in BytesMatch.from_yara_match(self._bytes, yara_match.match, self.highlight_style):
                decoder = BytesDecoder(match, yara_match.rule_name)
                self.extraction_stats.tally_match(decoder)
                yield match, decoder

        self._print_non_matches()

    def _yara_callback(self, data: dict) -> Callable:
        """
        Callback invoked by `yara-python` to handle matches and non-matches as they are discovered.

        Args:
            data (dict): Data provided when `yara-python` invokes the callback.

        Returns:
            Callable: Always returns `yara.CALLBACK_CONTINUE` to signal `yara-python` should continue processing.
        """
        if data['matches']:
            self.matches.append(YaraMatch(data, self._panel_text()))
        else:
            self.non_matches.append(data)

        return yara.CALLBACK_CONTINUE

    def _print_non_matches(self) -> None:
        """Print info about the YARA rules that didn't match the bytes."""
        if len(self.non_matches) == 0:
            return

        non_matches_text = sorted([Text(nm['rule'], 'grey') for nm in self.non_matches], key=str)

        # Only show the non matches if there were valid ones, otherwise just show the number
        if len(self.matches) == 0:
            non_match_desc = f" did not match any of the {len(self.non_matches)} yara rules"
            console.print(dim_if(self.__text__() + Text(non_match_desc, style='grey'), True))
            return

        non_match_desc = f" did not match the other {len(self.non_matches)} yara rules"
        console.print(self.__text__() + Text(non_match_desc, style='grey') + Text(': '), style='dim')
        console.print(Padding(Text(', ', 'white').join(non_matches_text), (0, 0, 1, 4)))

    def _panel_text(self) -> Text:
        """Inverted colors for the panel at the top of the match section of the output."""
        styles = [reverse_color(YARALYZER_THEME.styles[f"yara.{s}"]) for s in ('scanned', 'rules')]
        return self.__text__(*styles)

    def __text__(self, byte_style: Style | str = 'yara.scanned', rule_style: Style | str = 'yara.rules') -> Text:
        """Text representation of this YARA scan (__text__() was taken)."""
        txt = Text('').append(self.scannable_label, style=byte_style or 'yara.scanned')
        return txt.append(' scanned with <').append(self.rules_label, style=rule_style or 'yara.rules').append('>')

    def __rich_console__(self, _console: Console, options: ConsoleOptions) -> RenderResult:
        """Does the stuff. TODO: not the best place to put the core logic."""
        yield bytes_hashes_table(self._bytes, self.scannable_label)

        for _bytes_match, bytes_decoder in self.match_iterator():
            for attempt in bytes_decoder.__rich_console__(_console, options):
                yield attempt

    def __str__(self) -> str:
        """Plain text (no rich colors) representation of the scan for display."""
        return self.__text__().plain
