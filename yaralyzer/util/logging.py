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
import sys
from argparse import Namespace
from typing import Union

from rich.console import Console
from rich.logging import RichHandler

from yaralyzer.config import YaralyzerConfig

ARGPARSE_LOG_FORMAT = '{0: >29}    {1: <11} {2: <}\n'
LOG_FILE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
TRACE = 'TRACE'
TRACE_LEVEL = logging.DEBUG - 1

DEFAULT_LOG_HANDLER_KWARGS = {
    'console': Console(color_system='256', stderr=True),
    'omit_repeated_times': False,
    'rich_tracebacks': True,
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


def log_and_print(msg: str, log_level: str = 'INFO') -> None:
    """Both print (to console) and log (to file) a string."""
    log.log(logging.getLevelName(log_level), msg)
    print(msg)


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
    invocation_log.info(log_msg)
    log.info(log_msg)


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


def log_invocation() -> None:
    """Log the command used to launch the `yaralyzer` to the invocation log."""
    msg = f"THE INVOCATION: '{' '.join(sys.argv)}'"
    log.info(msg)
    invocation_log.info(msg)


def log_trace(*args) -> None:
    """Log below logging.DEBUG level."""
    log.log(TRACE_LEVEL, *args)


def set_log_level(level: Union[str, int]) -> None:
    """Set the log level at any time."""
    for handler in log.handlers + [log]:
        handler.setLevel(TRACE_LEVEL if level == TRACE else level)


# See file comment. 'log' is the standard application log, 'invocation_log' is a history of yaralyzer runs
log_console = DEFAULT_LOG_HANDLER_KWARGS['console']
log = configure_logger('run')
invocation_log = configure_logger('invocation')

# If we're logging to files make sure invocation_log has the right level
if YaralyzerConfig.LOG_DIR:
    invocation_log.setLevel('INFO')

# Suppress annoying chardet library logs
for submodule in ['universaldetector', 'charsetprober', 'codingstatemachine']:
    logging.getLogger(f"chardet.{submodule}").setLevel(logging.WARNING)
