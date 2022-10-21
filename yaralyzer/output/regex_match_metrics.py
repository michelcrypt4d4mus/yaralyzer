"""
Class to  measure what we enounter as we iterate over every single match of a relatively simple byte level regex
(e.g. "bytes between quotes") against a relatively large pool of close to random encrypted binary data

Things like how much many of our matched bytes were we able to decode easily vs. by force vs. not at all,
were some encodings have a higher pct of success than others (indicating part of our mystery data might be encoded
that way?

TODO: use @dataclass decorator https://realpython.com/python-data-classes/
"""
from collections import defaultdict

from yaralyzer.decoding.bytes_decoder import BytesDecoder
from yaralyzer.util.logging import log


class RegexMatchMetrics:
    def __init__(self) -> None:
        self.match_count = 0
        self.bytes_matched = 0
        self.matches_decoded = 0
        self.easy_decode_count = 0
        self.forced_decode_count = 0
        self.undecodable_count = 0
        self.skipped_matches_lengths = defaultdict(lambda: 0)
        self.bytes_match_objs = []  # Keep a copy of all matches in memory
        self.per_encoding_stats = defaultdict(lambda: RegexMatchMetrics())

    def num_matches_skipped_for_being_empty(self) -> int:
        return self.skipped_matches_lengths[0]

    def num_matches_skipped_for_being_too_big(self) -> int:
        return sum({k: v for k, v in self.skipped_matches_lengths.items() if k > 0}.values())

    def tally_match(self, decoder: BytesDecoder) -> None:
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
