"""
Class to smooth some of the rough edges around the dicts returned by chardet.detect_all()
"""
from typing import Any, Optional

from rich.text import Text

from yaralyzer.encoding_detection.character_encodings import ENCODING
from yaralyzer.helpers.rich_text_helper import (DIM_COUNTRY_THRESHOLD, meter_style,
     prefix_with_plain_text_obj)

CONFIDENCE = 'confidence'
LANGUAGE = 'language'


class EncodingAssessment:
    def __init__(self, assessment: dict) -> None:
        self.assessment = assessment
        self.encoding = assessment[ENCODING].lower()

        # Shift confidence from 0-1.0 scale to 0-100.0 scale
        self.confidence = 100.0 * (self._get_dict_empty_value_as_None(CONFIDENCE) or 0.0)
        self.confidence_text = prefix_with_plain_text_obj(f"{round(self.confidence, 1)}%", style=meter_style(self.confidence))

        # Add detected language info and label if any language was detected
        self.language = self._get_dict_empty_value_as_None(LANGUAGE)
        self.set_encoding_label(self.language.title() if self.language else None)

    @classmethod
    def dummy_encoding_assessment(cls, encoding) -> 'EncodingAssessment':
        """Generate an empty EncodingAssessment to use as a dummy when chardet gives us nothing."""
        assessment = cls({ENCODING: encoding, CONFIDENCE: 0.0})
        assessment.confidence_text = Text('none', 'no_attempt')
        return assessment

    def set_encoding_label(self, alt_text: Optional[str]) -> None:
        """Alt text is displayed below the encoding in slightly dimmer font."""
        self.encoding_label = Text(self.encoding, 'encoding.header')

        if alt_text is not None:
            dim = 'dim' if (self.confidence or 0.0) < DIM_COUNTRY_THRESHOLD else ''
            self.encoding_label.append(f" ({alt_text})", style=f"color(23) {dim}")

    def __rich__(self) -> Text:
        return Text('<Chardet(', 'white') + self.encoding_label + Text(':') + self.confidence_text + Text('>')

    def __str__(self) -> str:
        return self.__rich__().plain

    def _get_dict_empty_value_as_None(self, key: str) -> Any:
        """Return None if the value at :key is an empty string, empty list, etc."""
        value = self.assessment.get(key)

        if isinstance(value, (dict, list, str)) and len(value) == 0:
            return None
        else:
            return value
