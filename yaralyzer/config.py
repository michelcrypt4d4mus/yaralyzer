"""
Configuration management for Yaralyzer.
"""
import logging
import re
from argparse import _AppendAction, ArgumentParser, Namespace
from os import environ
from pathlib import Path
from typing import Any, Callable, TypeVar

from rich.text import Text
from rich_argparse_plus import RichHelpFormatterPlus

from yaralyzer.util.classproperty import classproperty
from yaralyzer.util.constants import KILOBYTE, YARALYZER_UPPER
from yaralyzer.util.helpers.collections_helper import listify
from yaralyzer.util.helpers.env_helper import (env_var_cfg_msg, is_env_var_set_and_not_false, is_invoked_by_pytest,
     is_path_var, print_env_var_explanation, stderr_console)
from yaralyzer.util.helpers.string_helper import is_number

LOG_DIR_ENV_VAR = "LOG_DIR"
LOG_LEVEL_ENV_VAR = "LOG_LEVEL"
T = TypeVar('T')

# These options cannot be read from an environment variable
ONLY_CLI_ARGS = [
    'env_vars',
    'extract_binary_streams',
    'file_to_scan_path',
    'help',
    'interact',
    'version',
]

# For when we need to build a default config outside of CLI usage. TODO: kinda janky
DEFAULT_ARGV = [
    __file__,
    '--regex-pattern', 'foobar',
    '--no-timestamps',
]


class YaralyzerConfig:
    """Handles parsing of command line args and environment variables for Yaralyzer."""

    # Env vars that configure yaralyzer command line options (or anything else) should be prefixed with this.
    ENV_VAR_PREFIX = YARALYZER_UPPER

    # These are passed through to `yara.set_config()``.
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

    # Logging stuff
    LOG_DIR: Path | None = None
    LOG_LEVEL: int = logging.WARNING

    # TODO: Is set in argument_parser.py. Hacky workaround to make our parse_arguments() available here
    _parse_arguments: Callable[[Namespace | None, list[str] | None], Namespace] = lambda args, argv: Namespace()
    _append_option_vars: list[str] = []
    _argparse_keys: list[str] = []

    @classproperty
    def args(cls) -> Namespace:
        if '_args' not in dir(cls):
            cls._set_default_args()

        return cls._args

    @classproperty
    def log_dir_env_var(cls) -> str:
        return cls.prefixed_env_var(LOG_DIR_ENV_VAR)

    @classmethod
    def env_var_for_command_line_option(cls, option: str) -> str:
        """'output_dir' becomes `YARALYZER_OUTPUT_DIR`. Overriden in pdfalyzer to distinguish yaralyzer only options."""
        return cls.prefixed_env_var(option)

    @classmethod
    def get_env_value(cls, var: str, var_type: Callable[[str], T] = str) -> T | None:
        """If called with `'output_dir'` it will check env value of `YARALYZER_OUTPUT_DIR`."""
        env_var = cls.env_var_for_command_line_option(var)
        env_value = environ.get(env_var)

        # Override type for a few important situations
        if not env_value:
            return None
        elif var.lower() in cls._append_option_vars:
            env_value = env_value.split(',')
        elif is_number(env_value):
            env_value = float(env_value) if '.' in env_value else int(env_value)
        else:
            env_value = var_type(env_value)

        if is_path_var(var):
            env_value = [Path(p) for p in env_value] if isinstance(env_value, list) else Path(env_value)

            for file_path in listify(env_value):
                if not file_path.exists():
                    raise EnvironmentError(f"Environment has {env_var} set to '{env_value}' but that path doesn't exist!")

        # print(f"Got value for var='{var}', env_var='{env_var}', value={env_value}")
        return env_value

    @classmethod
    def prefixed_env_var(cls, var: str) -> str:
        """Turns 'LOG_DIR' into 'YARALYZER_LOG_DIR' etc."""
        return (var if var.startswith(cls.ENV_VAR_PREFIX) else f"{cls.ENV_VAR_PREFIX}_{var}").upper()

    @classmethod
    def set_args(cls, _args: Namespace) -> None:
        """
        Set the `args` class instance variable and update args with any environment variable overrides.
        For each arg the environment will be checked for a variable with the same name, uppercased and
        prefixed by "YARALYZER_".

        Example:
            For the argument `--output-dir`, the environment will be checked for `YARALYZER_OUTPUT_DIR`.

        Args:
            _args (Namespace): Object returned by `ArgumentParser.parse_args()`
        """
        cls._args = _args

        for option in cls._argparse_keys:
            arg_value = vars(_args).get(option)
            env_value = cls.get_env_value(option)
            default_value = cls._get_default_arg(option)
            # print(f"option: {option}, arg_value: {arg_value}, env_var: {env_var}, env_value: {env_value}, default: {default_value}", file=stderr)  # noqa: E501

            # TODO: as is you can't override env vars with CLI args
            if isinstance(arg_value, bool):
                env_var = cls.prefixed_env_var(option)
                setattr(_args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                # Check against defaults to avoid overriding env var configured options
                if arg_value == default_value and env_value is not None:
                    setattr(_args, option, type(arg_value)(env_value) or arg_value)
            elif arg_value in ['', [], {}]:
                setattr(_args, option, env_value if env_value else arg_value)
            else:
                setattr(_args, option, arg_value or env_value)

    @classmethod
    def set_argument_parser(cls, parser: ArgumentParser) -> None:
        """Sets the `_argument_parser` instance variable that will be used to parse command line args."""
        cls._argument_parser = parser
        cls._argparse_keys = sorted([action.dest for action in parser._actions])
        cls._append_option_vars = [a.dest for a in parser._actions if isinstance(a, _AppendAction)]

    @classmethod
    def set_log_vars(cls) -> None:
        """Find any env vars related to logging and set them up. It's called immediately."""
        if (log_dir := cls.get_env_value(LOG_DIR_ENV_VAR, Path)):
            cls.LOG_DIR = Path(log_dir).resolve()

        if (log_level := cls.get_env_value(LOG_LEVEL_ENV_VAR)):
            cls.LOG_LEVEL = log_level_for(log_level)

        if cls.LOG_DIR and not is_invoked_by_pytest():
            stderr_console.print(f"Writing logs to '{cls.LOG_DIR}' instead of stderr/stdout...", style='dim')

    @classmethod
    def show_configurable_env_vars(cls) -> None:
        """
        Show the environment variables that can be used to set command line options, either
        permanently in a `.yaralyzer` file or in other standard environment variable ways.
        """
        stderr_console.print(env_var_cfg_msg(cls.ENV_VAR_PREFIX))

        for group in [g for g in cls._argument_parser._action_groups if 'positional' not in g.title]:
            stderr_console.print(f"\n# {group.title}", style=RichHelpFormatterPlus.styles["argparse.groups"])

            for action in group._group_actions:
                if not cls._is_configurable_by_env_var(action.dest):
                    continue

                var = cls.env_var_for_command_line_option(action.dest)
                print_env_var_explanation(var, action)

        print_env_var_explanation(cls.log_dir_env_var, 'writing of logs to files')

    @classmethod
    def _get_default_arg(cls, arg: str) -> Any:
        """Return the default value for `arg` as defined by a `DEFAULT_` style class variable."""
        default_var = f"DEFAULT_{arg.upper()}"
        return vars(cls).get(default_var)

    @classmethod
    def _is_configurable_by_env_var(cls, option: str) -> bool:
        """Returns `True` if this option can be configured by a `YARALYZER_VAR_NAME` style environment variable."""
        return not (option.startswith('export') or option in ONLY_CLI_ARGS)

    @classmethod
    def _set_default_args(cls) -> None:
        """Set `self.args` to their defaults as if parsed from the command line."""
        cls.set_args(cls._parse_arguments(None, DEFAULT_ARGV))
        cls.args.output_dir = Path(cls.args.output_dir or Path.cwd()).resolve()


YaralyzerConfig.set_log_vars()


def log_level_for(value: str | int) -> int:
    if isinstance(value, int):
        return value
    elif re.match(r"\d+", value):
        return int(value)
    elif value in logging.getLevelNamesMapping():
        return logging.getLevelNamesMapping()[value]
    else:
        raise ValueError(f"'{value}' is not a valid log level!")
