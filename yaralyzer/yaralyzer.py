import re
from collections import defaultdict
from os import path
from typing import Any, Dict, List, Optional, Union

import yara
from rich.padding import Padding
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.bytes_match import BytesMatch
from yaralyzer.helpers.file_helper import load_binary_data, load_file
from yaralyzer.helpers.rich_text_helper import YARALYZER_THEME, console, dim_if, reverse_color
from yaralyzer.output.regex_match_metrics import RegexMatchMetrics
from yaralyzer.util.logging import log
from yaralyzer.yara.yara_match import YaraMatch
from yaralyzer.yara.yara_rule_builder import yara_rule_string


class Yaralyzer:
    def __init__(self, bytes_to_scan: bytes, rules: yara.Rules, bytes_label: str, rules_label: str) -> None:
        self.bytes: bytes = bytes_to_scan
        self.bytes_length = len(bytes_to_scan)
        self.bytes_label: str = bytes_label
        self.rules: yara.Rules = rules
        self.rules_label: str = rules_label
        # Outcome racking variables
        self.suppression_notice_queue: list = []
        self.matches: List[YaraMatch] = []
        self.non_matches: List[dict] = []
        self.regex_extraction_stats: defaultdict = defaultdict(lambda: RegexMatchMetrics())

    @classmethod
    def for_rules_files(cls, file_to_scan: str, yara_rules_paths: List[str]) -> 'Yaralyzer':
        """Alternate constructor taking file paths as arguments"""
        yara_rules_string = "\n".join([load_file(file) for file in yara_rules_paths])
        rules_label = ", ".join([path.basename(rule_file) for rule_file in yara_rules_paths])

        return cls(
            bytes_to_scan=load_binary_data(file_to_scan),
            rules=yara.compile(source=yara_rules_string),
            bytes_label=path.basename(file_to_scan),
            rules_label=rules_label)

    @classmethod
    def for_patterns(cls, file_to_scan: str, patterns: List[str]) -> 'Yaralyzer':
        """Alternate constructor taking regex pattern strings as arguments"""
        rules = [yara_rule_string(pattern, f"rule_{i + 1}") for i, pattern in enumerate(patterns)]
        yara_rules_string = "\n".join(rules)
        rules_label = ", ".join(patterns)

        return cls(
            bytes_to_scan=load_binary_data(file_to_scan),
            rules=yara.compile(source=yara_rules_string),
            bytes_label=path.basename(file_to_scan),
            rules_label=rules_label)

    def yaralyze(self) -> None:
        """Use YARA to find matches and then force decode them"""
        self.rules.match(data=self.bytes, callback=self._yara_callback)

        for yara_match in self.matches:
            console.print(yara_match, Text("\n"))

            for match in BytesMatch.for_yara_strings_in_match(self.bytes, yara_match.match):
                BytesDecoder(match, yara_match.rule_name).print_decode_attempts()

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

    def __rich__(self) -> Text:
        return self._text_rep()

    def __str__(self) -> str:
        return self.__rich__().plain

    def _panel_text(self) -> Text:
        """Inverted colors for the panel at the top of the match section of the output"""
        styles = [reverse_color(YARALYZER_THEME.styles[f"yara.{s}"]) for s in ('scanned', 'rules')]
        return self._text_rep(*styles)

    def _text_rep(self, byte_style: Optional[Style] = None, rule_style: Optional[Style] = None) -> Text:
        """Text representation of this YARA scan"""
        txt = Text('').append(self.bytes_label, style=byte_style or 'yara.scanned')
        return txt.append(' scanned with <').append(self.rules_label, style=rule_style or 'yara.rules').append('>')
