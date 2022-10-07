"""
Methods for building Rich layout elements
"""
from typing import Optional, Union

from rich.table import Column, Table

from yaralyzer.helpers.bytes_helper import BytesInfo, get_bytes_info
from yaralyzer.helpers.rich_text_helper import LEFT, size_text
from yaralyzer.output.rich_console import GREY


def bytes_hashes_table(
        bytes_or_bytes_info: Union[bytes, BytesInfo],
        title: Optional[str] = None,
        title_justify: str = LEFT
    ) -> Table:
    if isinstance(bytes_or_bytes_info, bytes):
        bytes_info = get_bytes_info(bytes_or_bytes_info)
    else:
        bytes_info = bytes_or_bytes_info

    table = Table(
        'Size',
        Column(size_text(bytes_info.size)),
        title=title + ' Bytes Info' if title else None,
        title_style=GREY,
        title_justify=title_justify
    )
    table.add_row('MD5', bytes_info.md5)
    table.add_row('SHA1', bytes_info.sha1)
    table.add_row('SHA256', bytes_info.sha256)
    table.columns[1].style = 'orange3'
    table.columns[1].header_style = 'bright_cyan'
    return table
