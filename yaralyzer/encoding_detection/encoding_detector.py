"""
`EncodingDetector` class for managing chardet encoding detection.
"""
from dataclasses import dataclass, field
from operator import attrgetter

import chardet
from chardet.resultdict import ResultDict
from rich import box
from rich.padding import Padding
from rich.table import Table

from yaralyzer.config import YaralyzerConfig
from yaralyzer.encoding_detection.encoding_assessment import ENCODING, EncodingAssessment
from yaralyzer.output.theme import OFF_WHITE
from yaralyzer.util.logging import log

CONFIDENCE_SCORE_RANGE = range(0, 101)


@dataclass
class EncodingDetector:
    """
    Manager class to ease dealing with the encoding detection library `chardet`.

    Each instance of this class manages a `chardet.detect_all()` scan on a single set of bytes.

    Attributes:
        bytes (bytes): The bytes to analyze.
        assessments (list[EncodingAssessment]): List of `EncodingAssessment` objects from `chardet` results.
        force_decode_assessments (list[EncodingAssessment]): Assessments above force decode threshold.
        force_display_assessments (list[EncodingAssessment]): Assessments above force display threshold.
        has_any_idea (bool | None): `True` if `chardet` had any idea what the encoding might be,
            `False` if not, `None` if `chardet` wasn't run yet.
        raw_chardet_assessments (list[dict]): Raw list of dicts returned by `chardet.detect_all()`.
        table (Table): A rich `Table` object summarizing the chardet results.
        unique_assessments (list[EncodingAssessment]): Unique assessments by encoding, highest confidence only.
    """

    _bytes: bytes
    assessments: list[EncodingAssessment] = field(default_factory=list)
    force_decode_assessments: list[EncodingAssessment] = field(default_factory=list)
    force_display_assessments: list[EncodingAssessment] = field(default_factory=list)
    has_any_idea: bool | None = None
    raw_chardet_assessments: list[ResultDict] = field(default_factory=list)
    table: Table = field(default_factory=lambda: _empty_chardet_results_table())
    unique_assessments: list[EncodingAssessment] = field(default_factory=list)

    @property
    def bytes(self) -> bytes:
        return self._bytes

    @property
    def bytes_len(self) -> int:
        return len(self.bytes)

    def __post_init__(self) -> None:
        # Skip chardet if there's not enough bytes available
        if not self._has_enough_bytes():
            log.debug(f"{self.bytes_len} is not enough bytes to run chardet.detect()")
            return

        # Unique by encoding, ignoring language.  Ordered from highest to lowest confidence
        self.raw_chardet_assessments = chardet.detect_all(self.bytes, ignore_threshold=True)

        if len(self.raw_chardet_assessments) == 1 and self.raw_chardet_assessments[0][ENCODING] is None:
            log.info(f"chardet.detect() has no idea what the encoding is, result: {self.raw_chardet_assessments}")
            self.has_any_idea = False
            return

        self.has_any_idea = True
        self.assessments = [EncodingAssessment(a) for a in self.raw_chardet_assessments]
        self._uniquify_results_and_build_table()
        self.force_decode_assessments = self._assessments_above_confidence(YaralyzerConfig.args.force_decode_threshold)
        self.force_display_assessments = self._assessments_above_confidence(YaralyzerConfig.args.force_display_threshold)  # noqa: E501

    def get_encoding_assessment(self, encoding: str) -> EncodingAssessment:
        """
        Get the `chardet` assessment for a specific encoding.

        Args:
            encoding (str): The encoding to look for.

        Returns:
            EncodingAssessment: Assessment for the encoding if it exists, otherwise a dummy with 0 confidence.
        """
        assessment = next((r for r in self.unique_assessments if r.encoding == encoding), None)
        return assessment or EncodingAssessment.dummy_encoding_assessment(encoding)

    def _assessments_above_confidence(self, cutoff: float) -> list[EncodingAssessment]:
        """Return the assessments above the given confidence cutoff."""
        return [a for a in self.unique_assessments if a.confidence >= cutoff]

    def _has_enough_bytes(self) -> bool:
        """Return `True` if we have enough bytes to run `chardet.detect()`."""
        return self.bytes_len >= YaralyzerConfig.args.min_chardet_bytes

    def _uniquify_results_and_build_table(self) -> None:
        """Keep the highest result per encoding, ignoring the language `chardet` has indicated."""
        already_seen_encodings = {}

        for i, result in enumerate(self.assessments):
            if result.confidence < YaralyzerConfig.args.min_chardet_table_confidence:
                continue

            self.table.add_row(f"{i + 1}", result.encoding_label, result.confidence_text)

            # self.unique_assessments retains one result per encoding possibility (the highest confidence one)
            # Some encodings are not language specific and for those we don't care about the language
            if result.encoding not in already_seen_encodings:
                self.unique_assessments.append(result)
                already_seen_encodings[result.encoding] = result
            else:
                log.debug(f"Skipping chardet result {result} (already saw {already_seen_encodings[result.encoding]})")

        self.unique_assessments.sort(key=attrgetter('confidence'), reverse=True)

    def __rich__(self) -> Padding:
        return Padding(self.table, (0, 0, 0, 0))


def _empty_chardet_results_table() -> Table:
    """Returns an empty `Table` with appropriate columns for `chardet` results."""
    table = Table(
        'Rank', 'Encoding', 'Confidence',
        title='chardet.detect results',
        title_style='color(153) italic dim',
        header_style=OFF_WHITE,
        style='dim',
        box=box.SIMPLE,
        show_edge=False,
        collapse_padding=True
    )

    table.columns[0].justify = 'right'
    return table
