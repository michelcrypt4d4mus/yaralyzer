"""
Methods for computing and displaying various file hashes.
"""
import hashlib
from dataclasses import dataclass
from pathlib import Path
# from typing import Self  # TODO: this requires python 3.11

from rich.console import JustifyMethod
from rich.table import Column, Table

from yaralyzer.output.theme import GREY_COLOR
from yaralyzer.util.helpers.rich_helper import DEFAULT_TABLE_OPTIONS, size_text


@dataclass
class BytesInfo:
    """Compute the size, MD5, SHA1, and SHA256 hashes for some bytes."""

    _bytes: bytes

    @property
    def size(self) -> int:
        return len(self._bytes)

    @property
    def md5(self) -> str:
        return hashlib.md5(self._bytes).hexdigest().upper()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self._bytes).hexdigest().upper()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self._bytes).hexdigest().upper()

    def hash_dict(self) -> dict[str, str]:
        return {
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
        }

    @classmethod
    def for_file(cls, file_path: str | Path) -> 'BytesInfo':
        """Alternate constructor that reads the bytes from `file_path`."""
        return cls(Path(file_path).read_bytes())


def bytes_hashes_table(
    bytes_or_info: bytes | BytesInfo,
    title: str | None = None,
    title_justify: JustifyMethod = 'left'
) -> Table:
    """
    Build a Rich `Table` displaying the size, MD5, SHA1, and SHA256 hashes of a byte sequence.

    Args:
        bytes_or_info (Union[bytes, BytesInfo]): The `bytes` to hash, or a `BytesInfo`
            namedtuple with precomputed values.
        title (str | None, optional): Optional title for the table. Defaults to `None`.
        title_justify (JustifyMethod, optional): Justification for the table title. Defaults to `"LEFT"`.

    Returns:
        Table: A Rich `Table` object with the size and hash values.
    """
    bytes_info = bytes_or_info if isinstance(bytes_or_info, BytesInfo) else BytesInfo(bytes_or_info)

    table = Table(
        'Size',
        Column(size_text(bytes_info.size)),
        title=f" {title} Bytes Info" if title else None,
        title_style=GREY_COLOR,
        title_justify=title_justify,
        **DEFAULT_TABLE_OPTIONS,
    )

    table.columns[1].style = 'orange3'
    table.columns[1].header_style = 'bright_cyan'

    table.add_row('MD5', bytes_info.md5)
    table.add_row('SHA1', bytes_info.sha1)
    table.add_row('SHA256', bytes_info.sha256)
    return table
