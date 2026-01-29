"""
`BytesDecoder` class for attempting to decode bytes with various encodings.
"""
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from operator import attrgetter

from rich.align import Align
from rich.console import Console, ConsoleOptions, NewLine, RenderResult
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch  # Used to cause circular import issues
from yaralyzer.config import YaralyzerConfig
from yaralyzer.decoding.decoding_attempt import DecodingAttempt
from yaralyzer.encoding_detection.character_encodings import ENCODING, ENCODINGS_TO_ATTEMPT
from yaralyzer.encoding_detection.encoding_assessment import EncodingAssessment
from yaralyzer.encoding_detection.encoding_detector import EncodingDetector
from yaralyzer.util.helpers.collections_helper import get_dict_key_by_value
from yaralyzer.util.helpers.rich_helper import DEFAULT_TABLE_OPTIONS
from yaralyzer.output.decoding_attempts_table import new_decoding_attempts_table
from yaralyzer.output.decoding_table_row import DecodingTableRow
from yaralyzer.util.logging import log

# Multiply chardet scores by 100 (again) to make sorting the table easy
SCORE_SCALER = 100.0
# Text object defaults mostly for table entries
DECODING_ERRORS_MSG = Text('Yes', style='dark_red dim')
NO_DECODING_ERRORS_MSG = Text('No', style='green4 dim')
# A 2-tuple that can be indexed by booleans of messages used in the table to show true vs. false
WAS_DECODABLE_YES_NO = [NO_DECODING_ERRORS_MSG, DECODING_ERRORS_MSG]


@dataclass
class BytesDecoder:
    """
    Handles decoding a chunk of bytes into strings using various possible encodings, ranking and displaying results.

    This class leverages the `chardet` library and custom logic to try multiple encodings, track decoding outcomes,
    and present the results in a rich, user-friendly format. It is used to analyze and display the possible
    interpretations of a byte sequence, especially in the context of YARA matches or binary analysis.

    Attributes:
        bytes_match (BytesMatch): The `BytesMatch` instance being decoded.
        label (str, optional): Label for this decoding attempt, defaults to `bytes_match.label`.
        bytes (bytes): The bytes (including surrounding context) to decode.
        decoded_strings (dict[str, str]): Maps encoding to decoded string.
        decodings (list[DecodingAttempt]): DecodingAttempt objects for each encoding tried.
        encoding_detector (EncodingDetector): Used to detect and assess possible encodings.
        was_match_decodable (dict): Tracks successful decodes per encoding.
        was_match_force_decoded (dict): Tracks forced decodes per encoding.
        was_match_undecodable (dict): Tracks failed decodes per encoding.
    """
    bytes_match: BytesMatch
    label: str = ''
    # Non-arguments
    decoded_strings: dict[str, str] = field(default_factory=dict)
    decodings: list[DecodingAttempt] = field(default_factory=list)
    encoding_detector: EncodingDetector = field(init=False)
    was_match_decodable: defaultdict[str, int] = field(default_factory=lambda: _build_encodings_metric_dict())
    was_match_force_decoded: defaultdict[str, int] = field(default_factory=lambda: _build_encodings_metric_dict())
    was_match_undecodable: defaultdict[str, int] = field(default_factory=lambda: _build_encodings_metric_dict())

    @property
    def bytes(self) -> bytes:
        return self.bytes_match.surrounding_bytes

    def __post_init__(self):
        # Note we instantiate EncodingDetector both the match and surrounding bytes
        self.encoding_detector = EncodingDetector(self.bytes)
        self.label = self.label or self.bytes_match.label

    def _build_decodings_table(self, suppress_decodes: bool = False) -> Table:
        """
        First rows are the raw / hex views of the bytes, next rows are the attempted decodings.

        Args:
            suppress_decodes (bool, optional): If `True` don't add decoding attempts to the table. Defaults to `False`.
        """
        self.table = new_decoding_attempts_table(self.bytes_match)

        # Add the encoding rows to the table if not suppressed
        if not (YaralyzerConfig.args.suppress_decoding_attempts or suppress_decodes):
            self.decodings = [DecodingAttempt(self.bytes_match, encoding) for encoding in ENCODINGS_TO_ATTEMPT]
            # Attempt decodings we don't usually attempt if chardet is insistent enough
            forced_decodes = self._undecoded_assessments(self.encoding_detector.force_decode_assessments)
            self.decodings += [DecodingAttempt(self.bytes_match, a.encoding) for a in forced_decodes]

            # If we still haven't decoded chardet's top choice, decode it
            if len(self._forced_displays()) > 0 and not self._was_decoded(self._forced_displays()[0].encoding):
                chardet_top_encoding = self._forced_displays()[0].encoding
                log.info(f"Decoding {chardet_top_encoding} because it's chardet top choice...")
                self.decodings.append(DecodingAttempt(self.bytes_match, chardet_top_encoding))

            # Build the table rows from the decoding attempts
            rows = [self._row_from_decoding_attempt(decoding) for decoding in self.decodings]

            # Add assessments with no decode attempt
            rows += [
                DecodingTableRow.from_undecoded_assessment(a, a.confidence * SCORE_SCALER)
                for a in self._forced_displays()
            ]

            self._track_decode_stats()

            for row in sorted(rows, key=attrgetter('sort_score', 'encoding_label_plain'), reverse=True):
                self.table.add_row(*row.to_row_list())

        return self.table

    # TODO: rename this to something that makes more sense, maybe assessments_over_display_threshold()?
    def _forced_displays(self) -> list[EncodingAssessment]:
        """Returns assessments over the display threshold that are not yet decoded."""
        return self._undecoded_assessments(self.encoding_detector.force_display_assessments)

    def _undecoded_assessments(self, assessments: list[EncodingAssessment]) -> list[EncodingAssessment]:
        """Filter out the already decoded assessments from a set of assessments."""
        return [a for a in assessments if not self._was_decoded(a.encoding)]

    def _was_decoded(self, encoding: str) -> bool:
        """Check whether a given encoding is in the table already."""
        return any(row.encoding == encoding for row in self.decodings)

    def _decode_attempt_subheading(self) -> Panel:
        """Generate a rich.Panel for displaying decode attempts."""
        headline = Text(f"Found ", style='decode.subheading') + self.bytes_match.__rich__()
        return Panel(headline, style='decode.subheading', expand=False, **DEFAULT_TABLE_OPTIONS)

    def _track_decode_stats(self) -> None:
        """Track stats about successful vs. forced vs. failed decode attempts."""
        for decoding in self.decodings:
            if decoding.failed_to_decode:
                self.was_match_undecodable[decoding.encoding] += 1
                continue

            self.was_match_decodable[decoding.encoding] += 1

            if decoding.was_force_decoded:
                self.was_match_force_decoded[decoding.encoding] += 1

    def _row_from_decoding_attempt(self, decoding: DecodingAttempt) -> DecodingTableRow:
        """Create a `DecodingAttemptTable` row from a `DecodingAttempt`."""
        assessment = self.encoding_detector.get_encoding_assessment(decoding.encoding)

        # If the decoding can have a start offset add an appropriate extension to the encoding label
        if decoding.start_offset_label:
            if assessment.language:
                log.warning(f"{decoding.encoding} offset {decoding.start_offset} AND language '{assessment.language}'")
            else:
                assessment = deepcopy(assessment)
                assessment.set_encoding_label(decoding.start_offset_label)

        plain_decoded_string = decoding.decoded_string.plain
        sort_score = assessment.confidence * SCORE_SCALER

        # If the decoding result is a duplicate of a previous decoding, replace the decoded text
        # with "same output as X" where X is the previous encoding that gave the same result.
        if plain_decoded_string in self.decoded_strings.values():
            encoding_with_same_output = get_dict_key_by_value(self.decoded_strings, plain_decoded_string)
            display_text = Text('same output as ', style='color(66) dim italic')
            display_text.append(encoding_with_same_output, style=ENCODING).append('...', style='white')
        else:
            self.decoded_strings[decoding.encoding_label] = plain_decoded_string
            display_text = decoding.decoded_string

        # Set failures negative, shave off a little for forced decodes
        if decoding.failed_to_decode:
            sort_score = (sort_score * -1) - 100
        elif decoding.was_force_decoded:
            sort_score -= 10

        was_forced = WAS_DECODABLE_YES_NO[int(decoding.was_force_decoded)]
        return DecodingTableRow.from_decoded_assessment(assessment, was_forced, display_text, sort_score)

    def __rich_console__(self, _console: Console, options: ConsoleOptions) -> RenderResult:
        """Rich object generator (see Rich console docs)."""
        yield NewLine(2)
        yield Align(self._decode_attempt_subheading(), 'center')

        if not YaralyzerConfig.args.suppress_chardet:
            yield NewLine()
            yield Align(self.encoding_detector, 'center')
            yield NewLine()

        # In standalone mode we always print the hex/raw bytes # TODO this sucks
        if self.bytes_match.is_decodable():
            yield self._build_decodings_table()
        elif YaralyzerConfig.args._yaralyzer_standalone_mode:
            yield self._build_decodings_table(True)

        yield NewLine()
        yield Align(self.bytes_match.bytes_hashes_table(), 'center', style='dim')


def _build_encodings_metric_dict():
    """One key for each key in `ENCODINGS_TO_ATTEMPT`, values are all 0."""
    metrics_dict = defaultdict(lambda: 0)

    for encoding in ENCODINGS_TO_ATTEMPT.keys():
        metrics_dict[encoding] = 0

    return metrics_dict
