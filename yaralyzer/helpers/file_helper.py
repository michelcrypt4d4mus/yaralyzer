"""
Helper methods to work with files.
"""
from datetime import datetime
from pathlib import Path
from typing import List


def files_in_dir(_dir: Path | str, with_extname: str | None = None) -> List[Path]:
    """
    Returns paths for all non dot files in `dir` (optionally filtered to only those ending in 'with_extname').

    Args:
        dir (str): Directory to list files from.
        with_extname (Optional[str], optional): If set, only return files with this extension. Defaults to None.

    Returns:
        List[str]: List of file paths.
    """
    dir = Path(_dir)
    with_extname = f".{with_extname}" if (with_extname and not with_extname.startswith('.')) else ''
    glob_pattern = f"*{with_extname}"

    if not dir.is_dir():
        raise FileNotFoundError(f"'{_dir}' is not a directory!")

    return [f for f in dir.glob(glob_pattern) if not (f.name.startswith('.') or f.is_dir())]


def load_binary_data(file_path: Path | str) -> bytes:
    """Load and return the raw `bytes` from a file."""
    with open(file_path, 'rb') as f:
        return f.read()


def load_file(file_path: Path | str) -> str:
    """Load and return the text contents of a file."""
    with open(file_path, 'r') as f:
        return f.read()


def timestamp_for_filename() -> str:
    """Returns a string showing current time in a file name friendly format."""
    return datetime.now().strftime("%Y-%m-%dT%H.%M.%S")
