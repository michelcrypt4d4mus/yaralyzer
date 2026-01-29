"""
Handle logging for `yaralyzer`.

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
from argparse import Namespace
from contextlib import contextmanager
from copy import copy
from pathlib import Path
from typing import Any, Generator

from rich.console import Console
from rich.highlighter import ReprHighlighter
from rich.logging import RichHandler
from rich.text import Text

from yaralyzer.output.theme import LOG_THEME
from yaralyzer.util.constants import YARALYZER
from yaralyzer.util.helpers.env_helper import default_console_kwargs, is_github_workflow, is_invoked_by_pytest
from yaralyzer.util.helpers.file_helper import file_size_str, relative_path
from yaralyzer.util.helpers.string_helper import log_level_for

LOG_FILE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_SEPARATOR = '-' * 35
WRITE_STYLE = 'grey46'

DEFAULT_LOG_HANDLER_KWARGS = {
    'console': Console(stderr=True, theme=LOG_THEME, **default_console_kwargs()),
    'omit_repeated_times': False,
    'rich_tracebacks': True,
    'show_path': not is_invoked_by_pytest(),
    'show_time': not is_invoked_by_pytest(),
}


def configure_logger(config: type['YaralyzerConfig']) -> logging.Logger:  # noqa: F821
    """
    Set up a file or stream `logger` depending on the configuration.

    Args:
        config (YaralyzerConfig): Has LOG_DIR and LOG_LEVEL props

    Returns:
        logging.Logger: The configured `logger`.
    """
    logger = logging.getLogger(config.app_name.lower())
    rich_stream_handler = RichHandler(**DEFAULT_LOG_HANDLER_KWARGS)

    if config.LOG_DIR:
        if not (config.LOG_DIR.is_dir() and config.LOG_DIR.is_absolute()):
            raise FileNotFoundError(f"Log dir '{config.LOG_DIR}' doesn't exist or is not absolute")

        log_file_path = config.LOG_DIR.joinpath(f"{config.app_name}.log")
        log_file_handler = logging.FileHandler(log_file_path)
        log_file_handler.setFormatter(logging.Formatter(LOG_FILE_LOG_FORMAT))
        logger.addHandler(log_file_handler)
        rich_stream_handler.setLevel('WARN') # Rich handler is only for warnings when writing to log file

    logger.addHandler(rich_stream_handler)
    logger.setLevel(config.LOG_LEVEL)
    return logger


def invocation_str(_argv: list[str] | None = None, raw: bool = False) -> str:
    """Convert `sys.argv` into something readable by relativizing paths."""
    _argv = copy(_argv or sys.argv)

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


def log_and_print(msg: str, log_level: str = 'INFO', style: str = '') -> None:
    """Both print (to console) and log (to file) a string."""
    log.log(logging.getLevelName(log_level), msg)
    log_console.print(msg, style=style)


def log_bigly(msg: str, big_msg: object, level: int = logging.INFO) -> None:
    """Log something with newlines around it."""
    log.log(level, f"{msg}\n\n {big_msg}\n")


@contextmanager
def log_file_export(file_path: Path) -> Generator[Any, Any, Any]:
    """Standardize the way file exports are logged about."""
    if file_path.exists():
        log.debug(f"Overwriting existing '{file_path}' ({file_size_str(file_path)})...")
        file_path.unlink()

    started_at = time.perf_counter()
    yield file_path
    write_time = f"{time.perf_counter() - started_at:.3f} seconds"

    if file_path.exists():
        size = file_size_str(file_path)
        log_and_print(f"Wrote '{relative_path(file_path)}' in {write_time} ({size}).", style=WRITE_STYLE)
    else:
        log.error(f"Spent {write_time} writing file '{file_path}' but there's nothing there!")


def log_trace(*args) -> None:
    """Log below logging.DEBUG level."""
    log.log(logging.NOTSET, *args)


def set_log_level(level: str | int) -> None:
    """Set the log level at any time."""
    for handler in log.handlers + [log]:
        handler.setLevel(log_level_for(level))


# See file comment. 'log' is the standard application log, 'invocation_log' is a history of yaralyzer runs
log_console = DEFAULT_LOG_HANDLER_KWARGS['console']
log = logging.getLogger(YARALYZER)
highlighter = ReprHighlighter()

# Suppress annoying chardet library logs
for submodule in ['universaldetector', 'charsetprober', 'codingstatemachine']:
    logging.getLogger(f"chardet.{submodule}").setLevel(logging.WARNING)
