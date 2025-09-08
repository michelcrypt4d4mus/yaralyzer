"""
Helper methods to work with files.
"""
from datetime import datetime
from os import listdir, path
from typing import List, Optional


def timestamp_for_filename() -> str:
    """Returns a string showing current time in a file name friendly format."""
    return datetime.now().strftime("%Y-%m-%dT%H.%M.%S")


def files_in_dir(dir: str, with_extname: Optional[str] = None) -> List[str]:
    """
    Paths for non dot files, optionally ending in 'with_extname'.

    Args:
        dir (str): Directory to list files from.
        with_extname (Optional[str], optional): If set, only return files with this extension. Defaults to None.
    """
    files = [path.join(dir, path.basename(file)) for file in listdir(dir) if not file.startswith('.')]
    files = [file for file in files if not path.isdir(file)]

    if with_extname:
        return files_with_extname(files, with_extname)
    else:
        return files


def files_with_extname(files: List[str], extname: str) -> List[str]:
    """Return only files from the list that end with the given extname."""
    return [f for f in files if f.endswith(f".{extname}")]


def load_word_list(file_path):
    """For very simple files (1 col CSVs, if you will)."""
    with open(file_path, 'r') as f:
        return [line.rstrip().lstrip() for line in f.readlines()]


def load_binary_data(file_path) -> bytes:
    """Load and return the raw bytes from a file."""
    with open(file_path, 'rb') as f:
        return f.read()


def load_file(file_path) -> str:
    """Load and return the text contents of a file."""
    with open(file_path, 'r') as f:
        return f.read()
