"""
Configuration management for Yaralyzer.
"""
import platform
import re
import sys
from contextlib import contextmanager
from copy import deepcopy
from os import environ
from pathlib import Path
from shutil import get_terminal_size
from typing import Any, Generator, Literal, Mapping, Sequence

from dotenv import load_dotenv
from rich.console import Console

from yaralyzer.output.theme import LOG_THEME
from yaralyzer.util.constants import INVOKED_BY_PYTEST, dotfile_name
from yaralyzer.util.helpers.file_helper import relative_path

DEFAULT_CONSOLE_WIDTH = 160
DOTFILE_DIRS = [Path.cwd(), Path.home()]
NOTIFICATION_STYLE = 'dim'
PATH_ENV_VAR_REGEX = re.compile(r"^.*_(DIR|FILE|PATH)S?$", re.I)
PYTEST_REBUILD_FIXTURES_ENV_VAR = 'PYTEST_REBUILD_FIXTURES'

is_linux = lambda: platform.system().lower() == 'linux'
is_macos = lambda: platform.system().lower() == 'darwin'
is_windows = lambda: platform.system().lower() == 'windows'


# TODO: why is this a function?
def console_width_possibilities():
    """Returns a list of possible console widths, the first being the current terminal width."""
    # Subtract 2 from terminal cols just as a precaution in case things get weird
    return [get_terminal_size().columns - 2, DEFAULT_CONSOLE_WIDTH]


def is_cairosvg_installed() -> bool:
    """True if cairosvg package is available on the current system."""
    try:
        import cairosvg  # noqa: F401
        return True
    except (ModuleNotFoundError, OSError):
        return False


def is_env_var_set_and_not_false(var_name: str) -> bool:
    """Return `True` if `var_name` is not empty and set to anything other than "false" (capitalization agnostic)."""
    if var_name in environ:
        var_value = environ[var_name]
        return var_value is not None and len(var_value) > 0 and var_value.lower() != 'false'
    else:
        return False


def is_github_workflow() -> bool:
    return is_env_var_set_and_not_false('GITHUB_ACTION')


def is_invoked_by_pytest() -> bool:
    """Return `True` if invoked in a `pytest` context."""
    return is_env_var_set_and_not_false(INVOKED_BY_PYTEST)


def is_path_var(env_var_name: str) -> bool:
    """Returns True if `env_var_name` ends with _DIR or _PATH."""
    return bool(PATH_ENV_VAR_REGEX.match(env_var_name))


def load_dotenv_file(app_name: Literal['pdfalyzer', 'yaralyzer']) -> None:
    if is_invoked_by_pytest():
        return

    for dotenv_file in [dir.joinpath(dotfile_name(app_name)) for dir in DOTFILE_DIRS]:
        if dotenv_file.exists():
            load_dotenv(dotenv_path=dotenv_file)
            lines = [line for line in dotenv_file.read_text().split('\n') if line and not line.startswith('#')]
            stderr_notification(f"Loaded {len(lines)} vars from {relative_path(dotenv_file)}...")
            return


def stderr_notification(msg: str) -> None:
    """Show a message (usually at startup, before everything is setup)."""
    log_console.print(msg, style=NOTIFICATION_STYLE)


@contextmanager
def temporary_argv(new_argv: Sequence[str | Path]) -> Generator[Any, Any, Any]:
    """Temporarily replace sys.argv with something else."""
    old_argv = list(sys.argv)
    sys.argv = [str(arg) for arg in new_argv]

    try:
        yield
    finally:
        sys.argv = old_argv


@contextmanager
def temporary_env(env_vars: Mapping[str, str | Path]) -> Generator[Any, Any, Any]:
    """
    Temporarily add variables to the environemnt.
    See: https://shay-palachy.medium.com/temp-environment-variables-for-pytest-7253230bd777

    Example:
        with temporary_env({'new_var': 'new_value}):
            do_stuff()
    """
    old_environ = dict(environ)
    environ.update({k: str(v) for k, v in env_vars.items()})

    try:
        yield
    finally:
        environ.clear()
        environ.update(old_environ)


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

log_console = Console(
    color_system = DEFAULT_CONSOLE_KWARGS['color_system'],
    stderr=True,
    theme=LOG_THEME,
    width=max(console_width_possibilities())
)
# stderr_console.print(f"\n\n MAX WIDTH = {max(console_width_possibilities())}", style='bright_cyan')


# Pytest method, here only so Pdfalyzer can also access it.
def _should_rebuild_fixtures() -> bool:
    """
    True if pytest should overwrite fixture data with new output instead of comparing.
    It's here so that pdfalyzer can also use it.
    """
    return is_env_var_set_and_not_false(PYTEST_REBUILD_FIXTURES_ENV_VAR)
