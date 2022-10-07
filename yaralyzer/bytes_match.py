"""
Simple class to keep track of regex matches against binary data.  Basically an re.match object with
some (not many) extra bells and whistles, most notably the surrounding_bytes property.

pre_capture_len and post_capture_len refer to the regex sections before and after the capture group,
e.g. a regex like '123(.*)x:' would have pre_capture_len of 3 and post_capture_len of 2.
"""
import re
from typing import Iterator, Optional

from rich.text import Text

from yaralyzer.config import YaralyzerConfig
from yaralyzer.helpers.rich_text_helper import prefix_with_plain_text_obj
from yaralyzer.output.rich_console import GREY_ADDRESS
from yaralyzer.util.logging import log

# Regex Capture used when extracting quoted chunks of bytes
ALERT_STYLE = 'error'


class BytesMatch:
    def __init__(
            self,
            matched_against: bytes,
            start_idx: int,
            length: int,
            label: str,
            ordinal: int,
            match: Optional[re.Match] = None,  # It's rough to get the regex from yara :(
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> None:
        """
        Ordinal means it's the Nth match with this regex (not super important but useful)
        YARA makes it a little rouch to get the actual regex that matched. Can be done with plyara eventually.
        """
        self.matched_against: bytes = matched_against
        self.start_idx: int = start_idx
        self.end_idx: int = start_idx + length
        self.match_length: int = length
        self.length: int = length
        self.label: str = label
        self.ordinal: int = ordinal
        self.match: Optional[re.Match] = match
        # Maybe should be called "matched_bytes"
        self.bytes = matched_against[start_idx:self.end_idx]
        self.match_groups: Optional[tuple] = match.groups() if match else None
        self._find_surrounding_bytes()
        # Adjust the highlighting start point in case this match is very early in the stream
        self.highlight_start_idx = start_idx - self.surrounding_start_idx
        self.highlight_end_idx = self.highlight_start_idx + self.length
        self.highlight_style = highlight_style

    @classmethod
    def from_regex_match(
            cls,
            matched_against: bytes,
            match: re.Match,
            ordinal: int,
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> 'BytesMatch':
        return cls(matched_against, match.start(), len(match[0]), match.re.pattern, ordinal, match, highlight_style)

    @classmethod
    def from_yara_str(
            cls,
            matched_against: bytes,
            rule_name: str,
            yara_str: dict,
            ordinal: int,
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> 'BytesMatch':
        """Build a BytesMatch from a yara string match. matched_against is the set of bytes yara was run against"""
        # Don't duplicate the labeling if rule_name and yara_str are the same
        pattern_label = yara_str[1]

        if pattern_label == '$' + rule_name:
            label = pattern_label
        else:
            label = rule_name + ': ' + pattern_label

        return cls(
            matched_against=matched_against,
            start_idx=yara_str[0],
            length=len(yara_str[2]),
            label=label,
            ordinal=ordinal,
            highlight_style=highlight_style)

    @classmethod
    def from_yara_match(
            cls,
            matched_against: bytes,
            yara_match: dict,
            highlight_style: str = YaralyzerConfig.HIGHLIGHT_STYLE
        ) -> Iterator['BytesMatch']:
        """Iterator w/a BytesMatch for each string returned as part of a YARA match result dict."""
        for i, yara_str in enumerate(yara_match['strings']):
            yield(cls.from_yara_str(matched_against, yara_match['rule'], yara_str, i + 1, highlight_style))

    def style_at_position(self, idx) -> str:
        """Get the style for the byte at position idx within the matched bytes"""
        if idx < self.highlight_start_idx or idx >= self.highlight_end_idx:
            return GREY_ADDRESS
        else:
            return self.highlight_style

    def location(self) -> Text:
        """Returns a Text obj like '(start idx: 348190, end idx: 348228)'"""
        location_txt = prefix_with_plain_text_obj(f"(start idx: ", style='off_white', root_style='decode.subheading')
        location_txt.append(str(self.start_idx), style='number')
        location_txt.append(', end idx: ', style='off_white')
        location_txt.append(str(self.end_idx), style='number')
        location_txt.append(')', style='off_white')
        return location_txt

    def _find_surrounding_bytes(self, num_before: Optional[int] = None, num_after: Optional[int] = None) -> None:
        """Find the surrounding bytes, making sure not to step off the beginning or end"""
        num_after = num_after or num_before or YaralyzerConfig.NUM_SURROUNDING_BYTES
        num_before = num_before or YaralyzerConfig.NUM_SURROUNDING_BYTES
        self.surrounding_start_idx: int = max(self.start_idx - num_before, 0)
        self.surrounding_end_idx: int = min(self.end_idx + num_after, len(self.matched_against))
        self.surrounding_bytes: bytes = self.matched_against[self.surrounding_start_idx:self.surrounding_end_idx]

    def __rich__(self) -> Text:
        headline = prefix_with_plain_text_obj(str(self.match_length), style='number', root_style='decode.subheading')
        headline.append(f" bytes matching ")
        headline.append(f"{self.label} ", style=ALERT_STYLE if self.highlight_style == ALERT_STYLE else 'regex')
        headline.append('at ')
        return headline + self.location()

    def __str__(self):
        return self.__rich__().plain
