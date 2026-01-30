"""
Helper methods to work with bytes.
"""
import re
from io import StringIO
from sys import byteorder

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.text import Text

from yaralyzer.bytes_match import BytesMatch
from yaralyzer.config import YaralyzerConfig
from yaralyzer.encoding_detection.character_encodings import encoding_width
from yaralyzer.output.console import console, console_width
from yaralyzer.output.theme import BYTES, BYTES_BRIGHTER, BYTES_DECODED, BYTES_HIGHLIGHT, GREY_COLOR
from yaralyzer.util.helpers.rich_helper import newline_join
from yaralyzer.util.logging import log

NEWLINE_BYTE = b"\n"
SUBTABLE_MAX_WIDTH = console_width() - 35 - 5  # 35 for first 3 cols, 5 for in between hex and ascii

HEX_CHARS_PER_GROUP = 8
HEX_UNIT_LENGTH = (HEX_CHARS_PER_GROUP * 3) + HEX_CHARS_PER_GROUP + 4  # 4 for padding between groups
HEX_GROUPS_PER_LINE = divmod(SUBTABLE_MAX_WIDTH, HEX_UNIT_LENGTH)[0]
HEX_CHARS_PER_LINE = HEX_CHARS_PER_GROUP * HEX_GROUPS_PER_LINE


def ascii_view_of_raw_bytes(_bytes: bytes, bytes_match: BytesMatch) -> Text:
    """
    Return an ASCII view of raw bytes, highlighting the matched bytes.

    Args:
        _bytes (bytes): The full byte sequence.
        bytes_match (BytesMatch): The BytesMatch object indicating which bytes to highlight.

    Returns:
        Text: Rich Text object with highlighted match in ASCII view.
    """
    txt = Text('', style=BYTES)

    for i, b in enumerate(_bytes):
        if i < bytes_match.highlight_start_idx or i > bytes_match.highlight_end_idx:
            style1 = 'color(246)'
            style2 = 'color(234)'
        else:
            style1 = None
            style2 = None

        _byte = b.to_bytes(1, byteorder)

        if b < 32:
            txt.append('*', style=style2 or BYTES_BRIGHTER)
        elif b < 127:
            txt.append(_byte.decode('UTF-8'), style1 or BYTES_DECODED)
        elif b <= 160:
            txt.append('*', style=style2 or BYTES_HIGHLIGHT)
        else:
            txt.append('*', style=style2 or BYTES)

    segments = [txt[i:i + HEX_CHARS_PER_GROUP] for i in range(0, len(txt), HEX_CHARS_PER_GROUP)]

    lines = [
        Text('  ').join(segments[i:min(len(segments), i + HEX_GROUPS_PER_LINE)])
        for i in range(0, len(segments), HEX_GROUPS_PER_LINE)
    ]

    return newline_join(lines)


def clean_byte_string(bytes_array: bytes) -> str:
    r"""
    Return a clean string representation of bytes, without Python's b'' or b"" wrappers.
    e.g. '\x80\nx44' instead of "b'\x80\nx44'".

    Args:
        bytes_array (bytes): The bytes to convert.

    Returns:
        str: Clean string representation of the bytes.
    """
    byte_printer = Console(file=StringIO())
    byte_printer.out(bytes_array, end='')
    bytestr = byte_printer.file.getvalue()

    if bytestr.startswith("b'"):
        bytestr = bytestr.removeprefix("b'").removesuffix("'")
    elif bytestr.startswith('b"'):
        bytestr = bytestr.removeprefix('b"').removesuffix('"')
    else:
        raise RuntimeError(f"Unexpected byte string {bytestr}")

    return bytestr


def get_bytes_before_and_after_match(
    _bytes: bytes,
    match: re.Match,
    num_before: int | None = None,
    num_after: int | None = None
) -> bytes:
    """
    Get bytes before and after a regex match within a byte sequence.

    Args:
        _bytes (bytes): The full byte sequence.
        match (re.Match): The regex `Match` object.
        num_before (int, optional): Number of bytes before the match to include. Defaults to configured value.
        num_after (int, optional): Number of bytes after the match to include. Defaults to either configured value
            or the `num_before` arg value.

    Returns:
        bytes: The surrounding bytes including the match.
    """
    return get_bytes_surrounding_range(_bytes, match.start(), match.end(), num_before, num_after)


def get_bytes_surrounding_range(
    _bytes: bytes,
    start_idx: int,
    end_idx: int,
    num_before: int | None = None,
    num_after: int | None = None
) -> bytes:
    """
    Get bytes surrounding a specified range in a byte sequence.

    Args:
        _bytes (bytes): The full byte sequence.
        start_idx (int): Start index of the range.
        end_idx (int): End index of the range.
        num_before (int, optional): Number of bytes before the range. Defaults to configured value.
        num_after (int, optional): Number of bytes after the range. Defaults to configured value.

    Returns:
        bytes: The surrounding bytes including the range.
    """
    num_after = num_after or num_before or YaralyzerConfig.args.surrounding_bytes
    num_before = num_before or YaralyzerConfig.args.surrounding_bytes
    start_idx = max(start_idx - num_before, 0)
    end_idx = min(end_idx + num_after, len(_bytes))
    return _bytes[start_idx:end_idx]


def hex_view_of_raw_bytes(_bytes: bytes, bytes_match: BytesMatch) -> Text:
    """
    Return a hexadecimal view of raw bytes, highlighting the matched bytes.

    Args:
        _bytes (bytes): The full byte sequence.
        bytes_match (BytesMatch): The BytesMatch object indicating which bytes to highlight.

    Returns:
        Text: Rich Text object with highlighted match in hex view.
    """
    hex_str = hex_text(_bytes)
    highlight_start_idx = bytes_match.highlight_start_idx * 3
    highlight_end_idx = bytes_match.highlight_end_idx * 3
    hex_str.stylize(bytes_match.highlight_style, highlight_start_idx, highlight_end_idx)
    lines = hex_str.wrap(console, HEX_CHARS_PER_LINE * 3)
    return newline_join([Text('  ').join(line.wrap(console, HEX_CHARS_PER_GROUP * 3)) for line in lines])


def hex_string(_bytes: bytes) -> str:
    """
    Return a hex string representation of the given bytes.

    Args:
        _bytes (bytes): The bytes to convert.

    Returns:
        str: Hex string representation of the bytes.
    """
    return ' '.join([hex(b).removeprefix('0x').rjust(2, '0') for i, b in enumerate(_bytes)])


def hex_text(_bytes: bytes) -> Text:
    """
    Return a rich Text object of the hex string for the given bytes.

    Args:
        _bytes (bytes): The bytes to convert.

    Returns:
        Text: Rich Text object of the hex string.
    """
    return Text(hex_string(_bytes), style=GREY_COLOR)


def print_bytes(bytes_array: bytes, style: str | None = None, indent: int = 0) -> None:
    """
    Print a string representation of some bytes to the console.

    Args:
        bytes_array (bytes): The bytes to print.
        style (str, optional): Style to use for printing. Defaults to 'bytes'.
    """
    for line in bytes_array.split(NEWLINE_BYTE):
        padded_bytes = Padding(escape(clean_byte_string(line)), (0, 0, 0, indent))
        console.print(padded_bytes, style=style or 'bytes')


def rich_text_view_of_raw_bytes(_bytes: bytes, bytes_match: BytesMatch) -> Text:
    """
    Return a rich `Text` object of raw bytes, highlighting the matched bytes.

    Args:
        _bytes (bytes): The full byte sequence.
        bytes_match (BytesMatch): The BytesMatch object indicating which bytes to highlight.

    Returns:
        Text: Rich Text object with highlighted match.
    """
    surrounding_bytes_str = clean_byte_string(_bytes)
    highlighted_bytes_str = clean_byte_string(bytes_match.bytes)
    highlighted_bytes_str_length = len(highlighted_bytes_str)
    highlight_idx = _find_str_rep_of_bytes(surrounding_bytes_str, highlighted_bytes_str, bytes_match)

    txt = Text(surrounding_bytes_str[:highlight_idx], style=GREY_COLOR)
    matched_bytes_str = surrounding_bytes_str[highlight_idx:highlight_idx + highlighted_bytes_str_length]
    txt.append(matched_bytes_str, style=bytes_match.highlight_style)
    txt.append(surrounding_bytes_str[highlight_idx + highlighted_bytes_str_length:], style=GREY_COLOR)
    return txt


def truncate_for_encoding(_bytes: bytes, encoding: str) -> bytes:
    """
    Truncate bytes to a multiple of the character width for the given encoding.
    For example, for utf-16 this means truncating to a multiple of 2, for utf-32 to a multiple of 4.

    Args:
        _bytes (bytes): The bytes to truncate.
        encoding (str): The encoding to consider.

    Returns:
        bytes: Truncated bytes.
    """
    char_width = encoding_width(encoding)
    num_bytes = len(_bytes)
    num_extra_bytes = num_bytes % char_width

    if char_width <= 1 or num_bytes <= char_width or num_extra_bytes == 0:
        return _bytes
    else:
        return _bytes[:-num_extra_bytes]


def _find_str_rep_of_bytes(surrounding_bytes_str: str, highlighted_bytes_str: str, highlighted_bytes: BytesMatch):
    r"""
    Find the position of the highlighted bytes string within the surrounding bytes string.

    Both arguments are string representations of binary data. This is needed because the string
    representation of bytes can be longer than the actual bytes (e.g., '\\xcc' is 4 chars for 1 byte).

    Args:
        surrounding_bytes_str (str): String representation of the full byte sequence.
        highlighted_bytes_str (str): String representation of the matched bytes.
        highlighted_bytes (BytesMatch): The BytesMatch object for context.

    Returns:
        int: The index in the surrounding string where the highlighted bytes start, or -1 if not found.
    """
    # Start a few chars in to avoid errors: sometimes we're searching for 1 or 2 bytes and there's a false positive
    # in the extra bytes. This isn't perfect - it's starting us at the first index into the *bytes* that's safe to
    # check but this is almost certainly too soon given the large % of bytes that take 4 chars to print ('\x02' etc)
    highlight_idx = surrounding_bytes_str.find(highlighted_bytes_str, highlighted_bytes.highlight_start_idx)

    # TODO: Somehow \' and ' don't always come out the same :(
    if highlight_idx == -1:
        log.info(f"Failed to find highlighted_bytes in first pass so deleting single quotes and retrying. " +
                  "Highlighting may be off by a few chars,")

        surrounding_bytes_str = surrounding_bytes_str.replace("\\'", "'")
        highlight_idx = surrounding_bytes_str.find(highlighted_bytes_str)

        if highlight_idx == -1:
            log.warning(f"Failed to find\n{highlighted_bytes_str}\nin surrounding bytes:\n{surrounding_bytes_str}")
            log.warning("Highlighting will not work on this decoded string.")

    return highlight_idx
