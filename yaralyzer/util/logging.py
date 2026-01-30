"""
Logs are not normally ephemeral/not written to files but can be configured to do so by setting
the `YARALYZER_LOG_DIR` env var. See `.yaralyzer.example` for documentation about the side effects
of setting `YARALYZER_LOG_DIR` to a value.

* [logging.basicConfig](https://docs.python.org/3/library/logging.html#logging.basicConfig)

* [realpython.com/python-logging/](https://realpython.com/python-logging/)

Python log levels for reference:

```
    CRITICAL 50
    ERROR 40
    WARNING 30
    INFO 20
    DEBUG 10
    NOTSET 0
```
"""
import logging
import sys
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Generator

from rich.highlighter import ReprHighlighter
from rich.text import Text

from yaralyzer.util.constants import YARALYZER
from yaralyzer.util.helpers.env_helper import (is_github_workflow, is_invoked_by_pytest, log_console,
     stderr_notification)
from yaralyzer.util.helpers.file_helper import file_size_str, relative_path

LOG_FILE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_SEPARATOR = '-' * 35

DEFAULT_LOG_HANDLER_KWARGS = {
    'console': log_console,
    'omit_repeated_times': False,
    'rich_tracebacks': True,
    'show_path': not is_invoked_by_pytest(),
    'show_time': not is_invoked_by_pytest(),
}

log = logging.getLogger(YARALYZER)
highlighter = ReprHighlighter()


def invocation_str(_argv: list[str] | None = None, raw: bool = False) -> str:
    """Convert `sys.argv` into something readable by relativizing paths."""
    _argv = deepcopy(_argv or sys.argv)

    if not raw:
        _argv = [Path(_argv[0]).name] + [a if a.startswith('-') else str(relative_path(a)) for a in _argv[1:]]

    if is_github_workflow():
        _argv = [arg.replace('\\', '/') for arg in _argv]  # Adjust windows paths

    return "   " + ' '.join(_argv)


def invocation_txt() -> Text:
    txt = Text(f"Invoked with this command:\n\n")
    txt.append(f"{invocation_str()}\n\n", style='wheat4')

    # TODO: Ugly way to keep local system info out of fixture data
    if not is_invoked_by_pytest():
        txt.append(f"Invocation raw argv:\n\n", style='dim')
        txt.append(f"{invocation_str(raw=True)}", style='wheat4 dim')

    return txt


def log_bigly(msg: str, big_msg: object, level: int = logging.INFO) -> None:
    """Log something with newlines around it."""
    log.log(level, f"{msg}\n\n {big_msg}\n")


@contextmanager
def log_file_export(file_path: Path) -> Generator[Path, None, None]:
    """Standardize the way file exports are logged about."""
    if file_path.exists():
        log.debug(f"Overwriting existing '{file_path}' ({file_size_str(file_path)})...")
        file_path.unlink()

    started_at = time.perf_counter()
    yield file_path
    write_time = f"{time.perf_counter() - started_at:.3f} seconds"

    if file_path.exists():
        size = file_size_str(file_path)
        stderr_notification(f"Wrote '{relative_path(file_path)}' in {write_time} ({size}).")
    else:
        log.error(f"Spent {write_time} writing file '{file_path}' but there's nothing there!")


def log_trace(*args) -> None:
    """Log below logging.DEBUG level."""
    log.log(logging.NOTSET, *args)


# Suppress annoying chardet library logs
for submodule in ['universaldetector', 'charsetprober', 'codingstatemachine']:
    logging.getLogger(f"chardet.{submodule}").setLevel(logging.WARNING)
