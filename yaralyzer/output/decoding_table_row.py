from dataclasses import dataclass

from rich.text import Text

from yaralyzer.encoding_detection.encoding_assessment import EncodingAssessment
from yaralyzer.util.helpers.rich_helper import na_txt

DECODE_NOT_ATTEMPTED_MSG = Text('(decode not attempted)', style='decode.no_attempt')


@dataclass(kw_only=True)
class DecodingTableRow:
    encoding_label: Text
    confidence_text: Text
    was_forced_txt: Text
    decoded_txt: Text
    # Properties below here are not displayed in the table but are used for sorting etc.
    confidence: float
    encoding: str
    sort_score: float

    @property
    def encoding_label_plain(self) -> str:
        return self.encoding_label.plain

    @classmethod
    def from_decoded_assessment(
        cls,
        assessment: EncodingAssessment,
        was_forced_txt: Text,
        decoded_txt: Text,
        score: float
    ) -> 'DecodingTableRow':
        """
        Alternate constructor that builds a table row for a decoding attempt.

        Args:
            assessment (EncodingAssessment): The `chardet` assessment for the encoding used.
            was_forced_txt (Text): Text indicating if the decode was forced.
            decoded_txt (Text): The decoded string as a rich `Text` object (with highlighting).
            score (float): The score to use for sorting this row in the table.
        """
        return cls(
            encoding_label=assessment.encoding_label,
            confidence_text=assessment.confidence_text,
            was_forced_txt=was_forced_txt,
            decoded_txt=decoded_txt,
            confidence=assessment.confidence,
            encoding=assessment.encoding,
            sort_score=score,
        )

    @classmethod
    def from_undecoded_assessment(cls, assessment: EncodingAssessment, score: float) -> 'DecodingTableRow':
        """
        Alternate constructor for a row with just `chardet` assessment confidence data and no actual
        decoding attempt string.

        Args:
            assessment (EncodingAssessment): The `chardet` assessment for the encoding used.
            score (float): The score to use for sorting this row within the table.
        """
        return cls.from_decoded_assessment(assessment, na_txt(), DECODE_NOT_ATTEMPTED_MSG, score)

    def to_row_list(self) -> list[Text]:
        """Returns a row for the decoding attempts table."""
        return [self.encoding_label, self.confidence_text, self.was_forced_txt, self.decoded_txt]
