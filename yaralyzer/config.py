"""
Configuration management for Yaralyzer.
"""
import logging
from argparse import ArgumentParser, Namespace
from os import environ
from pathlib import Path
from typing import Any, Callable, List

from rich.console import Console

from yaralyzer.util.helpers.env_helper import DEFAULT_CONSOLE_KWARGS, is_env_var_set_and_not_false, is_invoked_by_pytest
from yaralyzer.util.classproperty import classproperty
from yaralyzer.util.constants import KILOBYTE, YARALYZER_UPPER

# These options cannot be read from an environment variable
ONLY_CLI_ARGS = [
    'file_to_scan_path',
    'help',
    'hex_patterns',
    'interact',
    'patterns_label',
    'regex_patterns',
    'regex_modifier',
    'version'
]

# For when we need to build a default config outside of CLI usage. TODO: kinda hacky
DEFAULT_ARGV = [
    __file__,
    '--regex-pattern', 'foobar',
    '--no-timestamps',
]


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
    LOG_LEVEL_ENV_VAR = f"{YARALYZER_UPPER}_LOG_LEVEL"
    LOG_LEVEL = logging.getLevelName(environ.get(LOG_LEVEL_ENV_VAR, 'WARN'))

    if LOG_DIR and not is_invoked_by_pytest():
        console = Console(stderr=True, **DEFAULT_CONSOLE_KWARGS)
        console.print(f"Writing logs to '{LOG_DIR}' instead of stderr/stdout...", style='dim')

    # TODO: Set in argument_parser.py, hacky workaround to make our parse_arguments() available here
    parse_arguments: Callable[[Namespace | None, list[str] | None], Namespace] = lambda args, argv: Namespace()

    @classproperty
    def args(cls) -> Namespace:
        if '_args' not in dir(cls):
            cls._set_default_args()

        return cls._args

    @classmethod
    def set_argument_parser(cls, parser: ArgumentParser) -> None:
        """Sets the `_argument_parser` instance variable that will be used to parse command line args."""
        cls._argument_parser: ArgumentParser = parser
        cls._argparse_keys: List[str] = sorted([action.dest for action in parser._actions])

    @classmethod
    def set_args(cls, _args: Namespace) -> None:
        """
        Set the `args` class instance variable and update args with any environment variable overrides.
        For each arg the environment will be checked for a variable with the same name, uppercased and
        prefixed by "YARALYZER_".

        Example:
            For the argument --output-dir, the environment will be checked for YARALYZER_OUTPUT_DIR.

        Args:
            _args (Namespace): Object returned by ArgumentParser.parse_ar()
        """
        cls._args = _args

        for option in cls._argparse_keys:
            if option.startswith('export') or option in ONLY_CLI_ARGS:
                continue

            arg_value = vars(_args)[option]
            env_var = f"{YARALYZER_UPPER}_{option.upper()}"
            env_value = environ.get(env_var)
            default_value = cls._get_default_arg(option)
            # print(f"option: {option}, arg_value: {arg_value}, env_var: {env_var}, env_value: {env_value}, default: {default_value}", file=stderr)  # noqa: E501

            # TODO: as is you can't override env vars with CLI args
            if isinstance(arg_value, bool):
                setattr(_args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                # Check against defaults to avoid overriding env var configured options
                if arg_value == default_value and env_value is not None:
                    setattr(_args, option, type(arg_value)(env_value) or arg_value)
            elif arg_value == '':
                setattr(_args, option, env_value if env_value else arg_value)
            else:
                setattr(_args, option, arg_value or env_value)

    @classmethod
    def _get_default_arg(cls, arg: str) -> Any:
        """Return the default value for `arg` as defined by a `DEFAULT_` style class variable."""
        default_var = f"DEFAULT_{arg.upper()}"
        return vars(cls).get(default_var)

    @classmethod
    def _set_default_args(cls) -> None:
        """Set `self.args` to their defaults as if parsed from the command line."""
        cls.set_args(cls.parse_arguments(None, DEFAULT_ARGV))
        cls.args.output_dir = Path(cls.args.output_dir or Path.cwd()).resolve()
