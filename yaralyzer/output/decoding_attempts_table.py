"""
Methods to build the `rich.table` used to display decoding attempts of a given bytes array.

Final output should be a `rich.table` of decoding attempts that are sorted like this:

    1. String representation of undecoded bytes is always the first row

    2. Encodings which `chardet.detect()` ranked as > 0% likelihood are sorted based on that confidence

    3. Then the unchardetectable:

        1. Decodings that were successful, unforced, and new

        2. Decodings that were "successful" but forced

        3. Decodings that were the same as other decodings

        4. Failed decodings
"""
from rich import box
from rich.table import Table
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.util.helpers.bytes_helper import (ascii_view_of_raw_bytes, hex_view_of_raw_bytes,
     rich_text_view_of_raw_bytes)
from yaralyzer.util.helpers.rich_helper import DEFAULT_TABLE_OPTIONS, na_txt

HEX = Text('HEX', style='bytes.title')
RAW_BYTES = Text('Raw', style=f"bytes")


def new_decoding_attempts_table(bytes_match: BytesMatch) -> Table:
    """Build a new rich `Table` with two rows, the raw and hex views of the `bytes_match` data."""
    table = Table(show_lines=True, border_style='bytes', header_style='decode.table_header', **DEFAULT_TABLE_OPTIONS)

    def add_col(title, **kwargs):
        kwargs['justify'] = kwargs.get('justify', 'center')
        table.add_column(title, overflow='fold', vertical='middle', **kwargs)

    add_col('Encoding', justify='right', width=12)
    add_col('Detect Odds', width=len('Detect'))
    add_col('Used\nForce?', width=len('Force?'))
    add_col('Decoded Output', justify='left')

    na = na_txt(style=HEX.style)
    table.add_row(HEX, na, na, _hex_preview_subtable(bytes_match))
    na = na_txt(style=RAW_BYTES.style)
    table.add_row(RAW_BYTES, na, na, rich_text_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match))
    return table


def _hex_preview_subtable(bytes_match: BytesMatch) -> Table:
    """
    Build a sub `Table` for hex view row (hex on one side, ascii on the other side).

    Args:
        bytes_match (BytesMatch): The `BytesMatch` object containing the bytes to display.

    Returns:
        Table: A `rich.table` with hex and ascii views of the bytes.
    """
    hex_table = Table(
        'hex',
        'ascii',
        border_style='grey.darkest',
        box=box.MINIMAL,
        header_style='decode.table_header',
        pad_edge=False,
        padding=(0, 1, 0, 2),
        show_lines=True,
        show_header=True,
        show_edge=False,
    )

    hex_table.add_row(
        hex_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match),
        ascii_view_of_raw_bytes(bytes_match.surrounding_bytes, bytes_match)
    )

    return hex_table
