"""
Helper methods to work with files.
"""
from datetime import datetime
from pathlib import Path

from yaralyzer.util.constants import KILOBYTE, MEGABYTE


def file_size(file_path: Path | str) -> int:
    return Path(file_path).stat().st_size


def file_size_str(file_path, digits: int | None = None):
    return file_size_to_str(file_size(file_path), digits)


def file_size_to_str(size: int, digits: int | None = None) -> str:
    _digits = 2

    if size > MEGABYTE:
        size_num = float(size) / MEGABYTE
        size_str = 'MB'
    elif size > KILOBYTE:
        size_num = float(size) / KILOBYTE
        size_str = 'kb'
        _digits = 1
    else:
        return f"{size} b"

    digits = _digits if digits is None else digits
    return f"{size_num:,.{digits}f} {size_str}"


def files_in_dir(_dir: Path | str, with_extname: str = '') -> list[Path]:
    """
    Returns paths for all non dot files in `dir` (optionally filtered to only those ending in 'with_extname').

    Args:
        dir (Path | str): Directory to list files from.
        with_extname (str | None): If set, only return files with this extension. Defaults to None.

    Returns:
        list[Path]: List of file paths.
    """
    dir = Path(_dir)
    with_extname = f".{with_extname}" if (with_extname and not with_extname.startswith('.')) else with_extname
    glob_pattern = f"*{with_extname}"

    if not dir.is_dir():
        raise FileNotFoundError(f"'{_dir}' is not a directory!")

    return [f for f in dir.glob(glob_pattern) if not (f.name.startswith('.') or f.is_dir())]


def load_file(file_path: Path | str) -> str:
    """Load and return the text contents of a file."""
    return Path(file_path).read_text(encoding='utf-8')  # Windows requires forcing the encoding


def relative_path(path: Path | str) -> Path:
    """Get path relative to current working directory."""
    try:
        return Path(path).relative_to(Path.cwd())
    except ValueError:
        return Path(path)


def timestamp_for_filename() -> str:
    """Returns a string showing current time in a file name friendly format."""
    return datetime.now().strftime("%Y-%m-%dT%H.%M.%S")


def to_paths(files: list[str] | list[Path] | list[str | Path]) -> list[Path]:
    return [Path(f) for f in files]
