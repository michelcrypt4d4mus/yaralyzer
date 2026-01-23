"""
Configuration management for Yaralyzer.
"""
from os import environ
from shutil import get_terminal_size

from yaralyzer.util.constants import INVOKED_BY_PYTEST, YARALYZER_UPPER

DEFAULT_CONSOLE_WIDTH = 160


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
