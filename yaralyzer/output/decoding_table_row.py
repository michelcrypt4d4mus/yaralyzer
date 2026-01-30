from dataclasses import dataclass, field

from rich.text import Text

from yaralyzer.encoding_detection.encoding_assessment import EncodingAssessment
from yaralyzer.util.helpers.rich_helper import na_txt

DECODE_NOT_ATTEMPTED_MSG = Text('(decode not attempted)', style='decode.no_attempt')


@dataclass
class DecodingTableRow:
    encoding_label: Text
    confidence_text: Text
    errors_while_decoded: Text  # This is really "is_forced"?
    decoded_string: Text
    # Properties below here are not displayed in the table but are used for sorting etc.
    confidence: float
    encoding: str
    sort_score: float
    encoding_label_plain: str = field(init=False)

    def __post_init__(self):
        self.encoding_label_plain = self.encoding_label.plain

    def to_row_list(self) -> list[Text]:
        """Returns a row for the decoding attempts table."""
        return [self.encoding_label, self.confidence_text, self.errors_while_decoded, self.decoded_string]

    @classmethod
    def from_decoded_assessment(
        cls,
        assessment: EncodingAssessment,
        is_forced: Text,
        txt: Text,
        score: float
    ) -> 'DecodingTableRow':
        """
        Alternate constructor that builds a table row for a decoding attempt.

        Args:
            assessment (EncodingAssessment): The `chardet` assessment for the encoding used.
            is_forced (Text): Text indicating if the decode was forced.
            txt (Text): The decoded string as a rich `Text` object (with highlighting).
            score (float): The score to use for sorting this row in the table.
        """
        return cls(
            encoding_label=assessment.encoding_label,
            confidence_text=assessment.confidence_text,
            errors_while_decoded=is_forced,
            decoded_string=txt,
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
