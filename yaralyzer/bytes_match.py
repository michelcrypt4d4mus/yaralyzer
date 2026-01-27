"""
`BytesMatch` class for tracking regex and YARA matches against binary data.
"""
import re
from dataclasses import dataclass, field
from typing import Iterator, Optional

from rich.table import Table
from rich.text import Text
from yara import StringMatch, StringMatchInstance

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.file_hashes_table import bytes_hashes_table
from yaralyzer.output.theme import BYTES_BRIGHTER, ERROR_STYLE, GREY_ADDRESS, OFF_WHITE
from yaralyzer.util.helpers.rich_helper import prefix_with_style


@dataclass
class BytesMatch:
    """
    Simple class to keep track of regex matches against binary data.

    Basically a Regex `re.match` object with some (not many) extra bells and whistles, most notably
    the `surrounding_bytes` property.

    Args:
        matched_against (bytes): The full byte sequence that was searched.
        start_idx (int): Start index of the match in the byte sequence.
        match_length (int): Length of the match in bytes.
        label (str): Label for the match (e.g., regex or YARA rule name).
        ordinal (int): This was the Nth match for this pattern (used for labeling only).
        match (re.Match, optional): Regex `match` object, if available.
        highlight_style (str, optional): Style to use for highlighting the match.

    Attributes:
        end_idx (int): End index of the match in the byte sequence.
        bytes: (bytes): The bytes that matched the regex.
    """
    matched_against: bytes
    start_idx: int
    match_length: int
    label: str
    ordinal: int
    match: re.Match | None = None   # It's rough to get the regex from yara :(
    highlight_style: str = BYTES_BRIGHTER
    end_idx: int = field(init=False)
    match_grooups: tuple = field(init=False)
    highlight_start_idx: int = field(init=False)
    highlight_end_idx: int = field(init=False)
    surrounding_start_idx: int = field(init=False)
    surrounding_end_idx: int = field(init=False)
    surrounding_bytes: bytes = field(init=False)

    def __post_init__(self):
        self.end_idx: int = self.start_idx + self.match_length
        self.bytes = self.matched_against[self.start_idx:self.end_idx]  # TODO: Maybe should be called "matched_bytes"
        self.match_groups: Optional[tuple] = self.match.groups() if self.match else None
        num_after = YaralyzerConfig.args.surrounding_bytes
        num_before = YaralyzerConfig.args.surrounding_bytes
        # Adjust the highlighting start point in case this match is very early or late in the stream
        self.surrounding_start_idx: int = max(self.start_idx - num_before, 0)
        self.surrounding_end_idx: int = min(self.end_idx + num_after, len(self.matched_against))
        self.surrounding_bytes: bytes = self.matched_against[self.surrounding_start_idx:self.surrounding_end_idx]
        self.highlight_start_idx = self.start_idx - self.surrounding_start_idx
        self.highlight_end_idx = self.highlight_start_idx + self.match_length

    @classmethod
    def from_regex_match(
        cls,
        matched_against: bytes,
        match: re.Match,
        ordinal: int,
        highlight_style: str = BYTES_BRIGHTER
    ) -> 'BytesMatch':
        """
        Alternate constructor to build a `BytesMatch` from a regex match object.

        Args:
            matched_against (bytes): The bytes searched.
            match (re.Match): The regex `match` object.
            ordinal (int): This was the Nth match for this pattern (used for labeling only).
            highlight_style (str, optional): Style for highlighting.

        Returns:
            BytesMatch: The constructed `BytesMatch` instance.
        """
        return cls(matched_against, match.start(), len(match[0]), match.re.pattern, ordinal, match, highlight_style)

    @classmethod
    def from_yara_str(
        cls,
        matched_against: bytes,
        rule_name: str,
        yara_str_match: StringMatch,
        yara_str_match_instance: StringMatchInstance,
        ordinal: int,
        highlight_style: str = BYTES_BRIGHTER
    ) -> 'BytesMatch':
        """
        Alternate constructor to build a `BytesMatch` from a YARA string match instance.

        Args:
            matched_against (bytes): The bytes searched.
            rule_name (str): Name of the YARA rule.
            yara_str_match (StringMatch): YARA string match object.
            yara_str_match_instance (StringMatchInstance): Instance of the string match.
            ordinal (int): The Nth match for this pattern.
            highlight_style (str, optional): Style for highlighting.

        Returns:
            BytesMatch: The constructed BytesMatch instance.
        """
        pattern_label = yara_str_match.identifier

        # Don't duplicate the labeling if rule_name and yara_str are the same
        if pattern_label == '$' + rule_name:
            label = pattern_label
        else:
            label = rule_name + ': ' + pattern_label

        return cls(
            matched_against=matched_against,
            start_idx=yara_str_match_instance.offset,
            match_length=yara_str_match_instance.matched_length,
            label=label,
            ordinal=ordinal,
            highlight_style=highlight_style
        )

    @classmethod
    def from_yara_match(
        cls,
        matched_against: bytes,
        yara_match: dict,
        highlight_style: str = BYTES_BRIGHTER
    ) -> Iterator['BytesMatch']:
        """
        Yield a `BytesMatch` for each string returned as part of a YARA match result dict.

        Args:
            matched_against (bytes): The bytes searched.
            yara_match (dict): YARA match result dictionary.
            highlight_style (str, optional): Style for highlighting.

        Yields:
            BytesMatch: For each string match in the YARA result.
        """
        i = 0  # For numbered labeling

        for yara_str_match in yara_match['strings']:
            for yara_str_match_instance in yara_str_match.instances:
                i += 1

                yield cls.from_yara_str(
                    matched_against,
                    yara_match['rule'],
                    yara_str_match,
                    yara_str_match_instance,
                    i,
                    highlight_style
                )

    def style_at_position(self, idx) -> str:
        """
        Get the style for the byte at position `idx` within the matched bytes.

        Args:
            idx (int): Index within the surrounding bytes.

        Returns:
            str: The style to use for this byte (highlight or greyed out).
        """
        if idx < self.highlight_start_idx or idx >= self.highlight_end_idx:
            return GREY_ADDRESS
        else:
            return self.highlight_style

    def location(self) -> Text:
        """
        Get a styled `Text` object describing the start and end index of the match.

        Returns:
            Text: Rich Text object like '(start idx: 348190, end idx: 348228)'.
        """
        location_txt = prefix_with_style(
            f"(start idx: ",
            style=OFF_WHITE,
            root_style='decode.subheading'
        )

        location_txt.append(str(self.start_idx), style='number')
        location_txt.append(', end idx: ', style=OFF_WHITE)
        location_txt.append(str(self.end_idx), style='number')
        location_txt.append(')', style=OFF_WHITE)
        return location_txt

    def is_decodable(self) -> bool:
        """
        Whether the bytes are decodable depends on whether `SUPPRESS_DECODES_TABLE` is set
        and whether the match length is between `MIN`/`MAX_DECODE_LENGTH`.

        Returns:
            bool: `True` if decodable, `False` otherwise.
        """
        return self.match_length >= YaralyzerConfig.args.min_decode_length \
           and self.match_length <= YaralyzerConfig.args.max_decode_length \
           and not YaralyzerConfig.args.suppress_decodes_table

    def bytes_hashes_table(self) -> Table:
        """
        Build a table of MD5/SHA hashes for the matched bytes.

        Returns:
            Table: Rich `Table` object with hashes.
        """
        return bytes_hashes_table(
            self.bytes,
            self.location().plain,
            'center'
        )

    def suppression_notice(self) -> Text:
        """
        Generate a message for when the match is too short or too long to decode.

        Returns:
            Text: Rich `Text` object with the suppression notice.
        """
        txt = self.__rich__()

        if self.match_length < YaralyzerConfig.args.min_decode_length:
            txt = Text('Too little to actually attempt decode at ', style='grey') + txt
        else:
            txt.append(" too long to decode ")
            txt.append(f"(--max-decode-length is {YaralyzerConfig.args.max_decode_length} bytes)", style='grey')

        return txt

    def to_json(self) -> dict:
        """
        Convert this `BytesMatch` to a JSON-serializable dictionary.

        Returns:
            dict: Dictionary representation of the match, suitable for JSON serialization.
        """
        json_dict = {
            'label': self.label,
            'match_length': self.match_length,
            'matched_bytes': self.bytes.hex(),
            'ordinal': self.ordinal,
            'start_idx': self.start_idx,
            'end_idx': self.end_idx,
            'surrounding_bytes': self.surrounding_bytes.hex(),
            'surrounding_start_idx': self.surrounding_start_idx,
            'surrounding_end_idx': self.surrounding_end_idx,
        }

        if self.match:
            json_dict['pattern'] = self.match.re.pattern

        return json_dict

    def __rich__(self) -> Text:
        """Get a rich `Text` representation of the match for display."""
        headline = prefix_with_style(str(self.match_length), style='number', root_style='decode.subheading')
        headline.append(f" bytes matching ")
        headline.append(f"{self.label} ", style=ERROR_STYLE if self.highlight_style == ERROR_STYLE else 'regex')
        headline.append('at ')
        return headline + self.location()

    def __str__(self):
        """Plain text (no rich colors) representation of the match for display."""
        return self.__rich__().plain
