"""
Methods for building Rich layout elements for display of results.
"""
import hashlib
from collections import namedtuple
from typing import Optional, Union

from rich.table import Column, Table

from yaralyzer.helpers.rich_text_helper import LEFT, size_text
from yaralyzer.output.rich_console import GREY

BytesInfo = namedtuple('BytesInfo', ['size', 'md5', 'sha1', 'sha256'])


def bytes_hashes_table(
        bytes_or_bytes_info: Union[bytes, BytesInfo],
        title: Optional[str] = None,
        title_justify: str = LEFT
    ) -> Table:
    """Build a table to show the MD5, SHA1, SHA256, etc."""
    if isinstance(bytes_or_bytes_info, bytes):
        bytes_info = compute_file_hashes(bytes_or_bytes_info)
    else:
        bytes_info = bytes_or_bytes_info

    table = Table(
        'Size',
        Column(size_text(bytes_info.size)),
        title=f" {title} Bytes Info" if title else None,
        title_style=GREY,
        title_justify=title_justify
    )
    table.add_row('MD5', bytes_info.md5)
    table.add_row('SHA1', bytes_info.sha1)
    table.add_row('SHA256', bytes_info.sha256)
    table.columns[1].style = 'orange3'
    table.columns[1].header_style = 'bright_cyan'
    return table


def compute_file_hashes(_bytes: bytes) -> BytesInfo:
    return BytesInfo(
        size=len(_bytes),
        md5=hashlib.md5(_bytes).hexdigest().upper(),
        sha1=hashlib.sha1(_bytes).hexdigest().upper(),
        sha256=hashlib.sha256(_bytes).hexdigest().upper()
    )


def compute_file_hashes_for_file(file_path) -> BytesInfo:
    with open(file_path, 'rb') as file:
        return compute_file_hashes(file.read())
