"""
Helps with `chardet` library.
"""
from dataclasses import dataclass, field
from typing import Any

from chardet.resultdict import ResultDict
from rich.text import Text

from yaralyzer.encoding_detection.character_encodings import ENCODING
from yaralyzer.util.helpers.rich_helper import meter_style, prefix_with_style

DIM_COUNTRY_THRESHOLD = 25
CONFIDENCE = 'confidence'
LANGUAGE = 'language'


@dataclass
class EncodingAssessment:
    """
    Class to smooth some of the rough edges around the `dict`s returned by `chardet.detect_all()`.

    Attributes:
        assessment (ResultDict): The dict returned by `chardet.detect_all()`.
        encoding (str): The encoding detected, in lowercase.
        confidence (float): Confidence score from 0.0 to 100.0.
        confidence_text (Text): Rich `Text` object representing the confidence with styling.
        language (Optional[str]): The detected language, if any.
        encoding_label (Text): Rich `Text` object for displaying the encoding with optional language info.
    """

    assessment: ResultDict
    confidence_text: Text = field(init=False)
    encoding_label: Text = field(init=False)

    @property
    def encoding(self) -> str:
        return (self.assessment.get(ENCODING) or '???').lower()

    @property
    def confidence(self) -> float:
        """Shift confidence from 0-1.0 scale to 0-100.0 scale"""
        return 100.0 * (self._get_empty_value_as_None(CONFIDENCE) or 0.0)

    @property
    def language(self) -> str | None:
        return self._get_empty_value_as_None(LANGUAGE)

    def __post_init__(self) -> None:
        self.confidence_text = prefix_with_style(f"{round(self.confidence, 1)}%", style=meter_style(self.confidence))
        # Add detected language info and label if any language was detected
        self.set_encoding_label(self.language.title() if self.language else None)

    @classmethod
    def dummy_encoding_assessment(cls, encoding: str) -> 'EncodingAssessment':
        """
        Construct an empty `EncodingAssessment` to use as a dummy when `chardet` gives us nothing.

        Args:
            encoding (str): The encoding to use for the dummy assessment.
        """
        assessment = cls(ResultDict(encoding=encoding, confidence=0.0, language=None))
        assessment.confidence_text = Text('none', 'decode.no_attempt')
        return assessment

    def set_encoding_label(self, alt_text: str | None) -> None:
        """
        Alt text is displayed below the encoding in slightly dimmer font.

        Args:
            alt_text (str | None): Text to display along with the encoding (often the inferred language)
        """
        self.encoding_label = Text(self.encoding, 'encoding.header')

        if alt_text is not None:
            dim = 'dim' if (self.confidence or 0.0) < DIM_COUNTRY_THRESHOLD else ''
            self.encoding_label.append(f" ({alt_text})", style=f"color(23) {dim}")

    def __rich__(self) -> Text:
        return Text('<Chardet(', 'white') + self.encoding_label + Text(':') + self.confidence_text + Text('>')

    def __str__(self) -> str:
        return self.__rich__().plain

    def _get_empty_value_as_None(self, key: str) -> Any:
        """Return `None` if the value at `key` is an empty string, empty list, etc."""
        value = self.assessment.get(key)

        if isinstance(value, (dict, list, str)) and len(value) == 0:
            return None
        else:
            return value
