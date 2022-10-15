"""
Methods to build the rich.table used to display decoding attempts of a given bytes array.

Final output should be rich.table of decoding attempts that are sorted like this:

    1. String representation of undecoded bytes is always the first row
    2. Encodings which chardet.detect() ranked as > 0% likelihood are sorted based on that confidence
    3. Then the unchardetectable:
        1. Decodings that were successful, unforced, and new
        2. Decodings that 'successful' but forced
        3. Decodings that were the same as other decodings
        4. Failed decodings
"""

from collections import namedtuple

from rich import box
from rich.table import Table
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.encoding_detection.encoding_assessment import EncodingAssessment
from yaralyzer.helpers.bytes_helper import (ascii_view_of_raw_bytes, hex_view_of_raw_bytes,
     rich_text_view_of_raw_bytes)
from yaralyzer.helpers.rich_text_helper import CENTER, FOLD, MIDDLE, RIGHT, na_txt

# The confidence and encoding will not be shown in the final display - instead their Text versions are shown
DecodingTableRow = namedtuple(
    'DecodingTableRow',
    [
        'encoding_text',
        'confidence_text',
        'errors_while_decoded',
        'decoded_string',
        'confidence',
        'encoding',
        'sort_score'
    ]
)

DECODE_NOT_ATTEMPTED_MSG = Text('(decode not attempted)', style='no_attempt')
HEX = Text('HEX', style='bytes.title')
RAW_BYTES = Text('Raw', style=f"bytes")


def build_decoding_attempts_table(bytes_match: BytesMatch) -> Table:
    """First rows are the raw / hex views of the bytes then 1 row per decoding attempt."""
    table = Table(show_lines=True, border_style='bytes', header_style='color(101) bold')

    def add_col(title, **kwargs):
        kwargs['justify'] = kwargs.get('justify', CENTER)
        table.add_column(title, overflow=FOLD, vertical=MIDDLE, **kwargs)

    add_col('Encoding', justify=RIGHT, width=12)
    add_col('Detect Odds', width=len('Detect'))
    add_col('Used\nForce?', width=len('Force?'))
    add_col('Decoded Output', justify='left')

    na = na_txt(style=HEX.style)
    table.add_row(HEX, na, na, _hex_preview_subtable(bytes_match))
    na = na_txt(style=RAW_BYTES.style)
    table.add_row(RAW_BYTES, na, na, rich_text_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match))
    return table


def decoding_table_row(assessment: EncodingAssessment, is_forced: Text, txt: Text, score: float) -> DecodingTableRow:
    """Get a table row for a decoding attempt"""
    return DecodingTableRow(
        assessment.encoding_text,
        assessment.confidence_text,
        is_forced,
        txt,
        assessment.confidence,
        assessment.encoding,
        sort_score=score)


def assessment_only_row(assessment: EncodingAssessment, score) -> DecodingTableRow:
    """Build a row with just chardet assessment data and no actual decoded string"""
    return decoding_table_row(assessment, na_txt(), DECODE_NOT_ATTEMPTED_MSG, score)


def _hex_preview_subtable(bytes_match: BytesMatch) -> Table:
    """Build a sub table for hex view (hex on one side, ascii on the other side)."""
    hex_table = Table(
        'hex',
        'ascii',
        border_style='color(235) dim',
        header_style='color(101) bold',
        box=box.MINIMAL,
        show_lines=True,
        show_header=True,
        show_edge=False,
        padding=(0, 1, 0, 2),
        pad_edge=False
    )

    hex_table.add_row(
        hex_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match),
        ascii_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match)
    )

    return hex_table
