import logging
from argparse import ArgumentParser, Namespace
from os import environ
from typing import Any, List

from rich.console import Console

YARALYZE = 'yaralyze'
YARALYZER = f"{YARALYZE}r".upper()
PYTEST_FLAG = 'INVOKED_BY_PYTEST'

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE


def config_var_name(env_var: str) -> str:
    """
    Get the name of env_var and strip off 'YARALYZER_', e.g.:
        SURROUNDING_BYTES_ENV_VAR = 'YARALYZER_SURROUNDING_BYTES'
        config_var_name(SURROUNDING_BYTES_ENV_VAR) => 'SURROUNDING_BYTES'
    """
    env_var = env_var.removeprefix("YARALYZER_")
    return f'{env_var=}'.partition('=')[0]


def is_env_var_set_and_not_false(var_name):
    """Returns True if var_name is not empty and set to anything other than 'false' (capitalization agnostic)"""
    if var_name in environ:
        var_value = environ[var_name]
        return var_value is not None and len(var_value) > 0 and var_value.lower() != 'false'
    else:
        return False


def is_invoked_by_pytest():
    """Return true if pytest is running"""
    return is_env_var_set_and_not_false(PYTEST_FLAG)


class YaralyzerConfig:
    # Passed through to yara.set_config()
    DEFAULT_MAX_MATCH_LENGTH = 100 * KILOBYTE
    DEFAULT_YARA_STACK_SIZE = 2 * 65536

    # Skip decoding binary matches under/over these lengths
    DEFAULT_MIN_DECODE_LENGTH = 1
    DEFAULT_MAX_DECODE_LENGTH = 256

    # chardet.detect() related
    DEFAULT_MIN_CHARDET_TABLE_CONFIDENCE = 2
    DEFAULT_MIN_CHARDET_BYTES = 9

    # Number of bytes to show before/after byte previews and decodes. Configured by command line or env var
    DEFAULT_SURROUNDING_BYTES = 64

    LOG_DIR_ENV_VAR = 'YARALYZER_LOG_DIR'
    LOG_DIR = environ.get(LOG_DIR_ENV_VAR)
    LOG_LEVEL_ENV_VAR = f"{YARALYZER}_LOG_LEVEL"
    LOG_LEVEL = logging.getLevelName(environ.get(LOG_LEVEL_ENV_VAR, 'WARN'))

    if LOG_DIR and not is_invoked_by_pytest():
        Console(color_system='256').print(f"Writing logs to '{LOG_DIR}' instead of stderr/stdout...", style='dim')

    HIGHLIGHT_STYLE = 'orange1'

    ONLY_CLI_ARGS = [
        'debug',
        'help',
        'hex_patterns',
        'interact',
        'patterns_label',
        'regex_patterns',
        'regex_modifier',
        'version'
    ]

    @classmethod
    def set_argument_parser(cls, parser: ArgumentParser) -> None:
        cls._argument_parser: ArgumentParser = parser
        cls._argparse_keys: List[str] = sorted([action.dest for action in parser._actions])

    @classmethod
    def set_args(cls, args: Namespace) -> None:
        cls.args = args

        for option in cls._argparse_keys:
            if option.startswith('export') or option in cls.ONLY_CLI_ARGS:
                continue

            arg_value = vars(args)[option]
            env_var = f"{YARALYZER}_{option.upper()}"
            env_value = environ.get(env_var)
            default_value = cls.get_default_arg(option)
            #print(f"option: {option}, arg_value: {arg_value}, env_var: {env_var}, env_value: {env_value}, default: {default_value}")

            # TODO: as is you can't override env vars with CLI args
            if isinstance(arg_value, bool):
                setattr(args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                # Check against defaults to avoid overriding env var configured options
                if arg_value == default_value and env_value is not None:
                    setattr(args, option, int(env_value) or arg_value)  # TODO: float args not handled
            else:
                setattr(args, option, arg_value or env_value)

    @classmethod
    def set_default_args(cls):
        cls.set_args(cls._argument_parser.parse_args(['dummy']))

    @classmethod
    def get_default_arg(cls, arg: str) -> Any:
        default_var = f"DEFAULT_{arg.upper()}"
        return vars(cls).get(default_var)
