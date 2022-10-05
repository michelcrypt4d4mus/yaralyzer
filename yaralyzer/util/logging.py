"""
There's two possible log sinks other than STDOUT:

  1. 'log' - the application log (standard log, what goes to STDOUT with -D option)
  2. 'invocation_log' - tracks the exact command yaralyzer was invoked with, similar to a history file

The regular log file at APPLICATION_LOG_PATH is where the quite verbose application logs
will be written if things ever need to get that formal. For now those logs are only accessible
on STDOUT with the -D flag but the infrastructure for persistent logging exists if someone
needs/wants that sort of thing.

Logs are not normally ephemeral/not written  to files but can be configured to do so by setting
the YARALYZER_LOG_DIR env var. See .yaralyzer.example for documentation about the side effects of setting
YARALYZER_LOG_DIR to a value.

https://docs.python.org/3/library/logging.html#logging.basicConfig
https://realpython.com/python-logging/

Python log levels for reference:
    CRITICAL 50
    ERROR 40
    WARNING 30
    INFO 20
    DEBUG 10
    NOTSET 0
"""
import logging
import sys
from os import environ, path

from rich.logging import RichHandler

from yaralyzer.config import YaralyzerConfig

ARGPARSE_LOG_FORMAT = '{0: >30}    {1: <17} {2: <}\n'


def configure_logger(log_label: str) -> logging.Logger:
    """Set up a file or stream logger depending on the configuration"""
    log_name = f"yaralyzer.{log_label}"
    logger = logging.getLogger(log_name)

    if YaralyzerConfig.LOG_DIR:
        if not path.isdir(YaralyzerConfig.LOG_DIR) or not path.isabs(YaralyzerConfig.LOG_DIR):
            raise RuntimeError(f"Log dir '{YaralyzerConfig.LOG_DIR}' doesn't exist or is not absolute")

        log_file_path = path.join(YaralyzerConfig.LOG_DIR, f"{log_name}.log")
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        log_file_handler = logging.FileHandler(log_file_path)
        log_file_handler.setFormatter(log_formatter)
        logger.addHandler(log_file_handler)
        # rich_stream_handler is for printing warnings
        rich_stream_handler = RichHandler(rich_tracebacks=True)
        rich_stream_handler.setLevel('WARN')
        logger.addHandler(rich_stream_handler)
        logger.info('File logging triggered by setting of YARALYZER_LOG_DIR')
    else:
        logger.addHandler(RichHandler(rich_tracebacks=True))

    logger.setLevel(YaralyzerConfig.LOG_LEVEL)
    return logger


# See comment at top. 'log' is the standard application log, 'invocation_log' is a history of yaralyzer runs
log = configure_logger('run')
invocation_log = configure_logger('invocation')

# If we're logging to files make sure invocation_log has the right level
if YaralyzerConfig.LOG_DIR:
    invocation_log.setLevel('INFO')


def log_and_print(msg: str, log_level='INFO'):
    """Both print and log (at INFO level) a string"""
    log.log(logging.getLevelName(log_level), msg)
    print(msg)


def log_current_config():
    """Write current state of YaralyzerConfig object to the logs"""
    msg = f"{YaralyzerConfig.__name__} current attributes:\n"
    config_dict = {k: v for k, v in vars(YaralyzerConfig).items() if not k.startswith('__')}

    for k in sorted(config_dict.keys()):
        msg += f"   {k: >35}  {config_dict[k]}\n"

    log.info(msg)


def log_invocation() -> None:
    """Log the command used to launch the yaralyzer to the invocation log"""
    msg = f"THE INVOCATION: '{' '.join(sys.argv)}'"
    log.info(msg)
    invocation_log.info(msg)


def log_argparse_result(args):
    """Logs the result of argparse"""
    args_dict = vars(args)
    log_msg = 'argparse results:\n' + ARGPARSE_LOG_FORMAT.format('OPTION', 'TYPE', 'VALUE')

    for arg_var in sorted(args_dict.keys()):
        arg_val = args_dict[arg_var]
        row = ARGPARSE_LOG_FORMAT.format(arg_var, type(arg_val).__name__, str(arg_val))
        log_msg += row

    log_msg += "\n"
    invocation_log.info(log_msg)
    log.info(log_msg)


# Suppress annoying chardet library logs
for submodule in ['universaldetector', 'charsetprober', 'codingstatemachine']:
    logging.getLogger(f"chardet.{submodule}").setLevel(logging.WARNING)
