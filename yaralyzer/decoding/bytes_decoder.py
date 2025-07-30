"""
Class to handle attempting to decode a chunk of bytes into strings with various possible encodings.
Leverages the chardet library to both guide what encodings are attempted as well as to rank decodings
in the results.
"""

from collections import defaultdict
from copy import deepcopy
from operator import attrgetter
from typing import List, Optional

from rich.align import Align
from rich.console import Console, ConsoleOptions, NewLine, RenderResult
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

#from yaralyzer.bytes_match import BytesMatch
from yaralyzer.config import YaralyzerConfig
from yaralyzer.decoding.decoding_attempt import DecodingAttempt
from yaralyzer.encoding_detection.character_encodings import ENCODING, ENCODINGS_TO_ATTEMPT, encoding_offsets
from yaralyzer.encoding_detection.encoding_assessment import EncodingAssessment
from yaralyzer.encoding_detection.encoding_detector import EncodingDetector
from yaralyzer.helpers.dict_helper import get_dict_key_by_value
from yaralyzer.helpers.list_helper import flatten
from yaralyzer.helpers.rich_text_helper import CENTER, DECODING_ERRORS_MSG, NO_DECODING_ERRORS_MSG
from yaralyzer.output.decoding_attempts_table import (DecodingTableRow, assessment_only_row,
     decoding_table_row, new_decoding_attempts_table)
from yaralyzer.util.logging import log

# A 2-tuple that can be indexed by booleans of messages used in the table to show true vs. false
WAS_DECODABLE_YES_NO = [NO_DECODING_ERRORS_MSG, DECODING_ERRORS_MSG]

# Multiply chardet scores by 100 (again) to make sorting the table easy
SCORE_SCALER = 100.0


class BytesDecoder:
    def __init__(self, bytes_match: 'BytesMatch', label: Optional[str] = None) -> None:
        self.bytes_match = bytes_match
        self.bytes = bytes_match.surrounding_bytes
        self.label = label or bytes_match.label

        # Empty table/metrics/etc
        self.was_match_decodable = _build_encodings_metric_dict()
        self.was_match_force_decoded = _build_encodings_metric_dict()
        self.was_match_undecodable = _build_encodings_metric_dict()
        self.decoded_strings = {}  # dict[encoding: decoded string]
        self.undecoded_rows = []
        self.decodings = []

        # Note we send both the match and surrounding bytes used when detecting the encoding
        self.encoding_detector = EncodingDetector(self.bytes)

    def __rich_console__(self, _console: Console, options: ConsoleOptions) -> RenderResult:
        """Rich object generator (see Rich console docs)"""
        yield NewLine(2)
        yield Align(self._decode_attempt_subheading(), CENTER)

        if not YaralyzerConfig.args.suppress_chardet:
            yield NewLine()
            yield Align(self.encoding_detector, CENTER)
            yield NewLine()

        # In standalone mode we always print the hex/raw bytes
        if self.bytes_match.is_decodable():
            yield self._build_decodings_table()
        elif YaralyzerConfig.args.standalone_mode:
            # TODO: yield self.bytes_match.suppression_notice() (i guess to show some notice that things are suppressed?)
            yield self._build_decodings_table(True)

        yield NewLine()
        yield Align(self.bytes_match.bytes_hashes_table(), CENTER, style='dim')

    def _build_decodings_table(self, suppress_decodes: bool = False) -> Table:
        """First rows are the raw / hex views of the bytes, next rows are the attempted decodings"""
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
            rows += [assessment_only_row(a, a.confidence * SCORE_SCALER) for a in self._forced_displays()]
            self._track_decode_stats()

            for row in sorted(rows, key=attrgetter('sort_score', 'encoding_label_plain'), reverse=True):
                self.table.add_row(*row[0:4])

        return self.table

    # TODO: rename this to something that makes more sense, maybe assessments_over_display_threshold()?
    def _forced_displays(self) -> List[EncodingAssessment]:
        """Returns assessments over the display threshold that are not yet decoded."""
        return self._undecoded_assessments(self.encoding_detector.force_display_assessments)

    def _undecoded_assessments(self, assessments: List[EncodingAssessment]) -> List[EncodingAssessment]:
        """Filter out the already decoded assessments from a set of assessments"""
        return [a for a in assessments if not self._was_decoded(a.encoding)]

    def _was_decoded(self, encoding: str) -> bool:
        """Check whether a given encoding is in the table already"""
        return any(row.encoding == encoding for row in self.decodings)

    def _decode_attempt_subheading(self) -> Panel:
        """Generate a rich.Panel for displaying decode attempts"""
        headline = Text(f"Found ", style='decode.subheading') + self.bytes_match.__rich__()
        return Panel(headline, style='decode.subheading', expand=False)

    def _track_decode_stats(self) -> None:
        """Track stats about successful vs. forced vs. failed decode attempts"""
        for decoding in self.decodings:
            if decoding.failed_to_decode:
                self.was_match_undecodable[decoding.encoding] += 1
                continue

            self.was_match_decodable[decoding.encoding] += 1

            if decoding.was_force_decoded:
                self.was_match_force_decoded[decoding.encoding] += 1

    def _row_from_decoding_attempt(self, decoding: DecodingAttempt) -> DecodingTableRow:
        """Create a DecodingAttemptTable row from a DecodingAttempt."""
        assessment = self.encoding_detector.get_encoding_assessment(decoding.encoding)

        # If the decoding can have a start offset add an appropriate extension to the encoding label
        if decoding.start_offset_label:
            if assessment.language:
                log.warning(f"{decoding.encoding} has offset {decoding.start_offset} and language '{assessment.language}'")
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
        return decoding_table_row(assessment, was_forced, display_text, sort_score)


def _build_encodings_metric_dict():
    """One key for each key in ENCODINGS_TO_ATTEMPT, values are all 0"""
    metrics_dict = defaultdict(lambda: 0)

    for encoding in ENCODINGS_TO_ATTEMPT.keys():
        metrics_dict[encoding] = 0

    return metrics_dict
