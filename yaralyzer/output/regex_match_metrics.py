"""
`RegexMatchMetrics` class.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.util.logging import log


@dataclass
class RegexMatchMetrics:
    """
    Class to measure what we enounter as we iterate over all matches of a relatively simple byte level regex.

    Things like how much many of our matched bytes were we able to decode easily vs. by force vs. not at all,
    were some encodings have a higher pct of success than others (indicating part of our mystery data might be
    encoded that way?

    Example:
        "Find bytes between quotes" against a relatively large pool of close to random encrypted binary data.

    Attributes:
        match_count (int): Total number of matches found.
        bytes_matched (int): Total number of bytes matched across all matches.
        matches_decoded (int): Number of matches where we were able to decode at least some of the matched bytes.
        easy_decode_count (int): Number of matches where we were able to decode the matched bytes without forcing.
        forced_decode_count (int): Number of matches where we were only able to decode the matched bytes by forcing.
        undecodable_count (int): Number of matches where we were unable to decode any of the matched bytes.
        skipped_matches_lengths (defaultdict): Dictionary mapping lengths of skipped matches to their counts.
        bytes_match_objs (list): List of `BytesMatch` objects for all matches encountered.
        per_encoding_stats (defaultdict): Dictionary mapping encoding names to their respective `RegexMatchMetrics`.
    """
    match_count: int = 0
    bytes_matched: int = 0
    matches_decoded: int = 0
    easy_decode_count: int = 0
    forced_decode_count: int = 0
    undecodable_count: int = 0
    skipped_matches_lengths: dict[int, int] = field(default_factory=lambda: defaultdict(lambda: 0))
    bytes_match_objs: list[BytesMatch] = field(default_factory=list)
    per_encoding_stats: dict[str, 'RegexMatchMetrics'] = \
        field(default_factory=lambda: defaultdict(lambda: RegexMatchMetrics()))

    def num_matches_skipped_for_being_empty(self) -> int:
        """Number of matches skipped for being empty (0 length)."""
        return self.skipped_matches_lengths[0]

    def num_matches_skipped_for_being_too_big(self) -> int:
        """Number of matches skipped for being too big to decode."""
        return sum({k: v for k, v in self.skipped_matches_lengths.items() if k > 0}.values())

    def tally_match(self, decoder: BytesDecoder) -> None:
        """
        Tally statistics from a `BytesDecoder` after it has processed a match.

        Args:
            decoder (BytesDecoder): The `BytesDecoder` that processed a match.
        """
        log.debug(f"Tallying {decoder.bytes_match} ({len(decoder.decodings)} decodings)")
        self.match_count += 1
        self.bytes_matched += decoder.bytes_match.match_length
        self.bytes_match_objs.append(decoder.bytes_match)

        if not decoder.bytes_match.is_decodable():
            self.skipped_matches_lengths[decoder.bytes_match.match_length] += 1

        for decoding_attempt in decoder.decodings:
            log.debug(f"Tallying decoding for {decoding_attempt.encoding}")
            encoding_stats = self.per_encoding_stats[decoding_attempt.encoding]

            if decoding_attempt.failed_to_decode:
                encoding_stats.undecodable_count += 1
            else:
                encoding_stats.match_count += 1
                encoding_stats.matches_decoded += 1

                if decoding_attempt.was_force_decoded:
                    encoding_stats.forced_decode_count += 1
                else:
                    encoding_stats.easy_decode_count += 1

    def __eq__(self, other):
        for k, v in vars(self).items():
            if v != vars(other)[k]:
                return False

        return True

    def __str__(self):
        return f"<matches: {self.match_count}, " + \
               f"bytes: {self.bytes_matched}, " + \
               f"decoded: {self.matches_decoded} " + \
               f"too_big: {self.num_matches_skipped_for_being_too_big()}, " + \
               f"empty: {self.num_matches_skipped_for_being_empty()}>" + \
               f"empty: {self.undecodable_count}>"
