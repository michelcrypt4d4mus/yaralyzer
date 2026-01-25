"""
Handle logging for `yaralyzer`.

There's two possible log sinks other than `STDOUT`:

  1. 'log' - the application log (standard log, what goes to `STDOUT` with `-D` option)
  2. 'invocation_log' - tracks the exact command yaralyzer was invoked with, similar to a history file

The regular log file at `APPLICATION_LOG_PATH` is where the quite verbose application logs
will be written if things ever need to get that formal. For now those logs are only accessible
on `STDOUT` with the `-D` flag but the infrastructure for persistent logging exists if someone
needs/wants that sort of thing.

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
import time
from argparse import Namespace
from copy import copy
from pathlib import Path
from sys import argv
from subprocess import CompletedProcess

from rich.console import Console
from rich.highlighter import ReprHighlighter
from rich.logging import RichHandler
from rich.text import Text
from rich.theme import Theme

from yaralyzer.config import YaralyzerConfig, log_level_for
from yaralyzer.util.constants import ECHO_COMMAND_OPTION, TRACE_LEVEL
from yaralyzer.util.helpers.env_helper import default_console_kwargs, is_invoked_by_pytest
from yaralyzer.util.helpers.file_helper import file_size_str, relative_path
from yaralyzer.util.helpers.string_helper import strip_ansi_colors

ARGPARSE_LOG_FORMAT = '{0: >29}    {1: <11} {2: <}\n'
LOG_FILE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_SEPARATOR = '-' * 35
WRITE_STYLE = 'grey46'

# TODO: unify themes
LOG_THEME = Theme({
    'repr.path': 'dark_orange3',
    'repr.filename': 'dark_orange3',
    'repr.none': 'grey23 italic',
})

DEFAULT_LOG_HANDLER_KWARGS = {
    'console': Console(stderr=True, theme=LOG_THEME, **default_console_kwargs()),
    'omit_repeated_times': False,
    'rich_tracebacks': True,
    'show_path': not is_invoked_by_pytest(),
    'show_time': not is_invoked_by_pytest(),
}


def configure_logger(log_label: str) -> logging.Logger:
    """
    Set up a file or stream `logger` depending on the configuration.

    Args:
        log_label (str): The label for the `logger`, e.g. "run" or "invocation".
            Actual name will be `"yaralyzer.{log_label}"`.

    Returns:
        logging.Logger: The configured `logger`.
    """
    log_name = f"yaralyzer.{log_label}"
    logger = logging.getLogger(log_name)
    rich_stream_handler = RichHandler(**DEFAULT_LOG_HANDLER_KWARGS)

    if YaralyzerConfig.LOG_DIR:
        if not (YaralyzerConfig.LOG_DIR.is_dir() and YaralyzerConfig.LOG_DIR.is_absolute()):
            raise FileNotFoundError(f"Log dir '{YaralyzerConfig.LOG_DIR}' doesn't exist or is not absolute")

        log_file_path = YaralyzerConfig.LOG_DIR.joinpath(f"{log_name}.log")
        log_file_handler = logging.FileHandler(log_file_path)
        log_file_handler.setFormatter(logging.Formatter(LOG_FILE_LOG_FORMAT))
        logger.addHandler(log_file_handler)
        rich_stream_handler.setLevel('WARN') # Rich handler is only for warnings when writing to log file

    logger.addHandler(rich_stream_handler)
    logger.setLevel(YaralyzerConfig.LOG_LEVEL)
    return logger


def invocation_str(_argv: list[str] | None = None, raw: bool = False) -> str:
    """Convert sys.argv into something readable."""
    _argv = copy(_argv or argv)
    _argv = [arg for arg in _argv if arg != ECHO_COMMAND_OPTION]

    if not raw:
        _argv = [Path(_argv[0]).name] + [a if a.startswith('-') else str(relative_path(a)) for a in _argv[1:]]

    return "   " + ' '.join(_argv)


def invocation_txt() -> Text:
    txt = Text(f"Invoked with this command:\n\n")
    txt.append(f"{invocation_str()}\n\n", style='wheat4')

    # TODO: Ugly way to keep local system info out of fixture data
    if not is_invoked_by_pytest():
        txt.append(f"Invocation raw argv:\n\n", style='dim')
        txt.append(f"{invocation_str(raw=True)}\n", style='wheat4 dim')

    return txt


def log_and_print(msg: str, log_level: str = 'INFO', style: str = '') -> None:
    """Both print (to console) and log (to file) a string."""
    log.log(logging.getLevelName(log_level), msg)
    log_console.print(msg, style=style)


def log_argparse_result(args: Namespace, label: str) -> None:
    """Logs the result of `argparse`."""
    args_dict = vars(args)
    log_msg = f'{label} argparse results:\n\n' + ARGPARSE_LOG_FORMAT.format('OPTION', 'TYPE', 'VALUE')
    log_msg += f"{ARGPARSE_LOG_FORMAT.format('------', '----', '-----')}"

    for arg_var in sorted(args_dict.keys()):
        arg_val = args_dict[arg_var]
        row = ARGPARSE_LOG_FORMAT.format(arg_var, type(arg_val).__name__, str(arg_val))
        log_msg += row

    log_msg += "\n"
    invocation_log.debug(log_msg)
    log.debug(log_msg)


def log_bigly(msg: str, big_msg: object, level: int = logging.WARNING) -> None:
    log_console.line()
    log.log(level, f"{msg}\n\n {big_msg}\n")


def log_current_config() -> None:
    """Write current state of `YaralyzerConfig` object to the logs."""
    msg = f"{YaralyzerConfig.__name__} current attributes:\n\n"

    config_dict = {
        k: v for k, v in vars(YaralyzerConfig).items()
        if not (k.startswith('_') or 'classmethod' in str(v))
    }

    for k in sorted(config_dict.keys()):
        msg += f"   {k: >35}  {config_dict[k]}\n"

    log.info(msg)


def log_file_write(file_path: str | Path, started_at: float) -> None:
    write_time = time.perf_counter() - started_at
    size = file_size_str(file_path)
    log_and_print(f"\nWrote '{relative_path(file_path)}' in {write_time:.2f} seconds ({size}).", style=WRITE_STYLE)


def log_invocation() -> None:
    """Log the command used to launch the `yaralyzer` to the invocation log."""
    msg = f"THE INVOCATION: '{' '.join(argv)}'"
    log.info(msg)
    invocation_log.info(msg)


def log_trace(*args) -> None:
    """Log below logging.DEBUG level."""
    log.log(TRACE_LEVEL, *args)


def set_log_level(level: str | int) -> None:
    """Set the log level at any time."""
    for handler in log.handlers + [log]:
        handler.setLevel(log_level_for(level))


def shell_command_log_str(result: CompletedProcess, ignore_args: list[str] | None = None) -> str:
    """Long string with all info about a shell command's execution and output."""
    cmd = invocation_str([arg for arg in result.args if arg not in (ignore_args or [])])
    msg = f"Return code {result.returncode} from shell command:\n\n{cmd}"

    for i, stream in enumerate([result.stdout, result.stderr]):
        label = 'stdout' if i == 0 else 'stderr'
        decoded_stream = stream.decode() if isinstance(stream, bytes) else stream
        decoded_stream = strip_ansi_colors(decoded_stream)
        msg += f"\n\n\n\n[{label}]\n{LOG_SEPARATOR}\n{decoded_stream}\n{LOG_SEPARATOR}"

    return msg + "\n"


# See file comment. 'log' is the standard application log, 'invocation_log' is a history of yaralyzer runs
log_console = DEFAULT_LOG_HANDLER_KWARGS['console']
log = configure_logger('run')
invocation_log = configure_logger('invocation')
highlighter = ReprHighlighter()

# If we're logging to files make sure invocation_log has the right level
if YaralyzerConfig.LOG_DIR:
    invocation_log.setLevel('INFO')

# Suppress annoying chardet library logs
for submodule in ['universaldetector', 'charsetprober', 'codingstatemachine']:
    logging.getLogger(f"chardet.{submodule}").setLevel(logging.WARNING)
