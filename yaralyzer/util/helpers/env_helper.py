"""
Configuration management for Yaralyzer.
"""
import re
import sys
from argparse import _AppendAction, _StoreTrueAction, Action
from contextlib import contextmanager
from copy import deepcopy
from os import environ
from shutil import get_terminal_size
from typing import Any, Generator

from rich.console import Console
from rich.padding import Padding
from rich.text import Text
from rich_argparse_plus import RichHelpFormatterPlus

from yaralyzer.output.theme import CLI_OPTION_TYPE_STYLES
from yaralyzer.util.cli_options.option_validator import OptionValidator
from yaralyzer.util.constants import INVOKED_BY_PYTEST, YARALYZER_UPPER, example_dotenv_file_url

DEFAULT_CONSOLE_WIDTH = 160
PATH_ENV_VAR_REGEX = re.compile(r".*_(DIR|FILE|PATH)S?", re.I)
PYTEST_REBUILD_FIXTURES_ENV_VAR = 'PYTEST_REBUILD_FIXTURES'


def config_var_name(env_var: str) -> str:
    """
    Get the name of `env_var` and strip off `YARALYZER_` prefix.

    Example:
        ```
        config_var_name('YARALYZER_SURROUNDING_BYTES') => 'SURROUNDING_BYTES'
        ```
    """
    env_var = env_var.removeprefix(f"{YARALYZER_UPPER}_")
    return f'{env_var=}'.partition('=')[0]


# TODO: why is this a function?
def console_width_possibilities():
    """Returns a list of possible console widths, the first being the current terminal width."""
    # Subtract 2 from terminal cols just as a precaution in case things get weird
    return [get_terminal_size().columns - 2, DEFAULT_CONSOLE_WIDTH]


def env_var_cfg_msg(app_name: str) -> Padding:
    app_name = app_name.lower()
    txt = Text(f"These are the environment variables can be set to configure {app_name}'s command line\n"
               f"options, either by conventional environment variable setting methods or by creating\na ")
    txt.append(f".{app_name} ", style='bright_cyan bold')
    txt.append(f"file in your home or current directory and putting these vars in it.\n\n"
               f"For more on how that works see the example env file here:\n\n   ")
    txt.append(f"{example_dotenv_file_url(app_name)}", style='cornflower_blue underline bold')
    return Padding(txt, (1, 1, 0, 2))


def is_cairosvg_installed() -> bool:
    """True if cairosvg package is available on the current system."""
    try:
        import cairosvg
        return True
    except ModuleNotFoundError:
        return False


def is_env_var_set_and_not_false(var_name: str) -> bool:
    """Return `True` if `var_name` is not empty and set to anything other than "false" (capitalization agnostic)."""
    if var_name in environ:
        var_value = environ[var_name]
        return var_value is not None and len(var_value) > 0 and var_value.lower() != 'false'
    else:
        return False


def is_invoked_by_pytest() -> bool:
    """Return `True` if invoked in a `pytest` context."""
    return is_env_var_set_and_not_false(INVOKED_BY_PYTEST)


def is_path_var(env_var_name: str) -> bool:
    """Returns True if `env_var_name` ends with _DIR or _PATH."""
    return bool(PATH_ENV_VAR_REGEX.match(env_var_name))


def print_env_var_explanation(env_var: str, action: str | Action) -> None:
    """Print a line explaiing which command line option corresponds to this env_var."""
    txt = Text('  ').append(f"{env_var:40}", style=RichHelpFormatterPlus.styles["argparse.args"])
    option = action.option_strings[-1] if isinstance(action, Action) else action
    comment = ''

    if is_path_var(env_var):
        option_type = 'Path'
    elif isinstance(action, _StoreTrueAction):
        option_type = 'bool'
    elif 'type' in vars(action) and (_option_type := getattr(action, 'type')) is not None:
        #print(f"\n\n_option_type='{_option_type}', type(_option_type)= {type(_option_type)}\n\n")
        if isinstance(_option_type, OptionValidator):
            option_type = _option_type.arg_type_str()
        else:
            option_type = _option_type.__name__
    else:
        option_type = 'string'

    if isinstance(action, _AppendAction):
        comment = ' (comma separated for multiple)'

    # stderr_console.print(f"env_var={env_var}, acitoncls={type(action).__name__}, action.type={action.type}")
    txt.append(f' {option_type:8} ', style=CLI_OPTION_TYPE_STYLES.get(option_type, 'white') + ' dim')
    txt.append(' sets ').append(option, style='honeydew2')
    txt.append(comment, style='dim')
    stderr_console.print(txt)


@contextmanager
def temporary_argv(new_argv: list[str]) -> Generator[Any, Any, Any]:
    """Temporarily replace sys.argv with something else."""
    old_argv = list(sys.argv)
    sys.argv = list(new_argv)

    try:
        yield
    finally:
        sys.argv = old_argv


@contextmanager
def temporary_env(env_vars: dict[str, str]) -> Generator[Any, Any, Any]:
    """
    Temporarily add variables to the environemnt.
    See: https://shay-palachy.medium.com/temp-environment-variables-for-pytest-7253230bd777

    Example:
        with temporary_env({'new_var': 'new_value}):
            do_stuff()
    """
    old_environ = dict(environ)
    environ.update(env_vars)

    try:
        yield
    finally:
        environ.clear()
        environ.update(old_environ)


def _should_rebuild_fixtures() -> bool:
    """
    True if pytest should overwrite fixture data with new output instead of comparing.
    It's here so that pdfalyzer can also use it.
    """
    return is_env_var_set_and_not_false(PYTEST_REBUILD_FIXTURES_ENV_VAR)


# Maximize output width if YARALYZER_MAXIMIZE_WIDTH is set (also can changed with --maximize-width option)
if is_invoked_by_pytest():
    CONSOLE_WIDTH = DEFAULT_CONSOLE_WIDTH
elif is_env_var_set_and_not_false('YARALYZER_MAXIMIZE_WIDTH'):
    CONSOLE_WIDTH = max(console_width_possibilities())
else:
    CONSOLE_WIDTH = min(console_width_possibilities())

DEFAULT_CONSOLE_KWARGS = {
    'color_system': '256',
    'width': CONSOLE_WIDTH,
}


def default_console_kwargs() -> dict[str, str | int]:
    """Returns a fresh copy of DEFAULT_CONSOLE_KWARGS."""
    return deepcopy(DEFAULT_CONSOLE_KWARGS)


# For use when you need to write output before the main rich.console has managed to get set up.
stderr_console = Console(stderr=True, **DEFAULT_CONSOLE_KWARGS)
