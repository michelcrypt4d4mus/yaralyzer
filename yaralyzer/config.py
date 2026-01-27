"""
Configuration management for Yaralyzer.
"""
import logging
import re
from argparse import _AppendAction, ArgumentParser, Namespace
from os import environ
from pathlib import Path
from typing import Any, Callable, TypeVar

from yaralyzer.output.theme import YARALYZER_THEME_DICT
from yaralyzer.util.classproperty import classproperty
from yaralyzer.util.constants import KILOBYTE, YARALYZE, YARALYZER_UPPER
from yaralyzer.util.helpers.collections_helper import listify
from yaralyzer.util.helpers.debug_helper import print_stack
from yaralyzer.util.helpers.env_helper import (is_env_var_set_and_not_false,
     is_invoked_by_pytest, is_path_var, load_dotenv_file, stderr_console, temporary_argv)
from yaralyzer.util.helpers.string_helper import is_falsey, is_number, is_truthy, log_level_for

LOG_DIR_ENV_VAR = "LOG_DIR"
LOG_LEVEL_ENV_VAR = "LOG_LEVEL"
T = TypeVar('T')

# For when we need to build a default config outside of CLI usage. TODO: kinda janky
DEFAULT_ARGV = [YARALYZE, __file__, '--regex-pattern', 'foobar']


class YaralyzerConfig:
    """Handles parsing of command line args and environment variables for Yaralyzer."""

    ENV_VAR_PREFIX = YARALYZER_UPPER     # Yaralyzer env vars are always prefixed with this
    COLOR_THEME = YARALYZER_THEME_DICT   # Overloaded in pdfalyzer

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
    # EncodingDetector defaults
    DEFAULT_FORCE_DISPLAY_THRESHOLD = 20.0
    DEFAULT_FORCE_DECODE_THRESHOLD = 50.0

    # Logging stuff
    LOG_DIR: Path | None = None
    LOG_LEVEL: int = logging.WARNING

    # These options cannot be read from an environment variable
    ONLY_CLI_ARGS = [
        'env_vars',
        'file_to_scan_path',
        'help',
        'interact',
        'version',
    ]

    _append_option_vars: list[str] = []
    _argparse_dests: list[str] = []
    _parse_arguments: Callable[[type['YaralyzerConfig'], Namespace | None], Namespace]

    @classproperty
    def app_name(cls) -> str:
        return cls.ENV_VAR_PREFIX.strip('_').title()

    @classproperty
    def args(cls) -> Namespace:
        """Source for parsed command line arguments merged with environment variable options."""
        if '_args' not in dir(cls):
            cls._set_default_args()

        return cls._args

    @classproperty
    def executable_name(cls) -> str:
        """The command used to run this app, e.g. `'yaralyze'`."""
        return cls.app_name.lower().removesuffix('r')

    @classproperty
    def log_dir_env_var(cls) -> str:
        """Environment variable name that can set the log output directory."""
        return cls.prefixed_env_var(LOG_DIR_ENV_VAR)

    @classmethod
    def init(
        cls,
        argparser: ArgumentParser,
        parse_arguments: Callable[[type['YaralyzerConfig'], Namespace | None], Namespace]
    ) -> None:
        """
        Should be called immediately upon package load.

        Args:
            argparser (ArgumentParser): An ArgumentParser that can parse the args this app needs.
            parse_arguments (Callable): Function that can fill in and error check what `argparser.parse_args()` returns.
        """
        cls._set_class_vars_from_env()
        cls._argument_parser = argparser
        cls._argparse_dests = sorted([action.dest for action in argparser._actions])
        cls._append_option_vars = [a.dest for a in argparser._actions if isinstance(a, _AppendAction)]
        cls._parse_arguments = parse_arguments

    @classmethod
    def env_var_for_command_line_option(cls, option: str) -> str:
        """`output_dir' becomes``YARALYZER_OUTPUT_DIR`. Overriden in pdfalyzer to distinguish yaralyzer only options."""
        return cls.prefixed_env_var(option)

    @classmethod
    def get_env_value(cls, var: str, var_type: Callable[[str], T] = str) -> T | None:
        """If called with `'output_dir'` it will check env value of `YARALYZER_OUTPUT_DIR`."""
        env_var = cls.env_var_for_command_line_option(var)
        env_value = environ.get(env_var)
        var = var.removeprefix(f"{cls.ENV_VAR_PREFIX}_").lower()  # Accomodates being called with YARALYZER_OUTPUT_DIR

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
        if is_falsey(str(env_value)):
            return False
        elif is_truthy(str(env_value)):
            return True
        else:
            return env_value

    @classmethod
    def parse_args(cls) -> Namespace:
        """Parse `sys.argv` and merge the result with any options set in the environment variables."""
        args = cls._parse_arguments(cls, None)
        cls._merge_env_options(args)
        return args

    @classmethod
    def prefixed_env_var(cls, var: str) -> str:
        """Turns 'LOG_DIR' into 'YARALYZER_LOG_DIR' etc."""
        return (var if var.startswith(cls.ENV_VAR_PREFIX) else f"{cls.ENV_VAR_PREFIX}_{var}").upper()

    @classmethod
    def _get_default_arg(cls, arg: str) -> Any:
        """Return the default value for `arg` as defined by a `DEFAULT_` style class variable."""
        return vars(cls).get(f"DEFAULT_{arg.upper()}")

    @classmethod
    def _is_configurable_by_env_var(cls, option: str) -> bool:
        """Returns `True` if this option can be configured by a `YARALYZER_VAR_NAME` style environment variable."""
        return not (option.startswith('export') or option in cls.ONLY_CLI_ARGS)

    @classmethod
    def _merge_env_options(cls, _args: Namespace) -> None:
        """
        Set the `args` class instance variable and update args with any environment variable overrides.
        For each arg the environment will be checked for a variable with the same name, uppercased and
        prefixed by "YARALYZER_".

        Example:
            For the argument `--output-dir` the environment will be checked for `YARALYZER_OUTPUT_DIR`.

        Args:
            _args (Namespace): Object returned by `ArgumentParser.parse_args()`
        """
        cls._args = _args

        for option in cls._argparse_dests:
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

        cls.args.output_dir = (cls.args.output_dir or Path.cwd()).resolve()
        cls.args.file_prefix = (cls.args.file_prefix + '__') if cls.args.file_prefix else ''
        cls.args.file_suffix = ('_' + cls.args.file_suffix) if cls.args.file_suffix else ''

    @classmethod
    def _set_class_vars_from_env(cls) -> None:
        """Check the environment for LOG_LEVEL and LOG_DIR so the log setter upper can use them."""
        load_dotenv_file(cls.app_name.lower())

        if (log_dir := cls.get_env_value(LOG_DIR_ENV_VAR, Path)):
            cls.LOG_DIR = Path(log_dir).resolve()

        if (log_level := cls.get_env_value(LOG_LEVEL_ENV_VAR)):
            cls.LOG_LEVEL = log_level_for(log_level)

        if cls.LOG_DIR and not is_invoked_by_pytest():
            stderr_console.print(f"Writing logs to '{cls.LOG_DIR}' instead of stderr/stdout...", style='dim')

    @classmethod
    def _set_default_args(cls) -> None:
        """Set `self.args` to their defaults as if parsed from the command line."""
        from yaralyzer.util.logging import log
        log.warning(f"{type(cls).__name__}._set_default_args() called which shouldn't be happening any more.")
        # print_stack()

        with temporary_argv(DEFAULT_ARGV):
            cls._merge_env_options(cls._parse_arguments(cls, None))
