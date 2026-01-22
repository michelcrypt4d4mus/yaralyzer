"""
Configuration management for Yaralyzer.
"""
import logging
from argparse import ArgumentParser, Namespace
from os import environ
from pathlib import Path
from typing import Any, List

from rich.console import Console

from yaralyzer.helpers.env_helper import DEFAULT_CONSOLE_KWARGS, is_env_var_set_and_not_false, is_invoked_by_pytest
from yaralyzer.util.classproperty import classproperty
from yaralyzer.util.constants import YARALYZER

DEFAULT_CONSOLE_WIDTH = 160
KILOBYTE = 1024


class YaralyzerConfig:
    """Handles parsing of command line args and environment variables for Yaralyzer."""

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

    # logging module requires absolute paths
    LOG_DIR_ENV_VAR = 'YARALYZER_LOG_DIR'
    LOG_DIR = Path(environ.get(LOG_DIR_ENV_VAR)).resolve() if environ.get(LOG_DIR_ENV_VAR) else None
    LOG_LEVEL_ENV_VAR = f"{YARALYZER}_LOG_LEVEL"
    LOG_LEVEL = logging.getLevelName(environ.get(LOG_LEVEL_ENV_VAR, 'WARN'))

    if LOG_DIR and not is_invoked_by_pytest():
        Console(**DEFAULT_CONSOLE_KWARGS).print(f"Writing logs to '{LOG_DIR}' instead of stderr/stdout...", style='dim')

    HIGHLIGHT_STYLE = 'orange1'

    _ONLY_CLI_ARGS = [
        'debug',
        'help',
        'hex_patterns',
        'interact',
        'patterns_label',
        'regex_patterns',
        'regex_modifier',
        'version'
    ]

    @classproperty
    def args(cls) -> Namespace:
        if '_args' not in dir(cls):
            cls.set_default_args()

        return cls._args

    @classmethod
    def set_argument_parser(cls, parser: ArgumentParser) -> None:
        """Sets the `_argument_parser` instance variable that will be used to parse command line args."""
        cls._argument_parser: ArgumentParser = parser
        cls._argparse_keys: List[str] = sorted([action.dest for action in parser._actions])

    @classmethod
    def set_args(cls, _args: Namespace) -> None:
        """Set the `args` class instance variable and update args with any environment variable overrides."""
        cls._args = _args

        for option in cls._argparse_keys:
            if option.startswith('export') or option in cls._ONLY_CLI_ARGS:
                continue

            arg_value = vars(_args)[option]
            env_var = f"{YARALYZER}_{option.upper()}"
            env_value = environ.get(env_var)
            default_value = cls.get_default_arg(option)
            # print(f"option: {option}, arg_value: {arg_value}, env_var: {env_var}, env_value: {env_value}, default: {default_value}")  # noqa: E501

            # TODO: as is you can't override env vars with CLI args
            if isinstance(arg_value, bool):
                setattr(_args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                # Check against defaults to avoid overriding env var configured options
                if arg_value == default_value and env_value is not None:
                    setattr(_args, option, int(env_value) or arg_value)  # TODO: float args not handled
            else:
                setattr(_args, option, arg_value or env_value)

    @classmethod
    def set_default_args(cls) -> None:
        """Set `self.args` to their defaults as if parsed from the command line."""
        cls.set_args(cls._argument_parser.parse_args([__file__]))

    @classmethod
    def get_default_arg(cls, arg: str) -> Any:
        """Return the default value for `arg` as defined by a `DEFAULT_` style class variable."""
        default_var = f"DEFAULT_{arg.upper()}"
        return vars(cls).get(default_var)
