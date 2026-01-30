"""
Holds the rich.Console instance that controls the stdout printing and file export.
"""
from copy import deepcopy
from os import devnull
from sys import argv

from rich.console import Console
from rich.errors import MarkupError
from rich.text import Text

from yaralyzer.util.constants import SUPPRESS_OUTPUT_OPTION
from yaralyzer.util.helpers.env_helper import DEFAULT_CONSOLE_KWARGS, log_console
from yaralyzer.output.theme import YARALYZER_THEME


console_kwargs = deepcopy(DEFAULT_CONSOLE_KWARGS)

if SUPPRESS_OUTPUT_OPTION in argv:
    log_console.print(f"Suppressing terminal output because {SUPPRESS_OUTPUT_OPTION} is enabled...", style='dim')
    console_kwargs.update({'file': open(devnull, "wt")})

# This is the global stdout manager
console = Console(highlight=False, theme=YARALYZER_THEME, **console_kwargs)


def console_print_with_fallback(_string: Text | str, style=None) -> None:
    """`rich.console.print()` with fallback to regular `print()` if there's a Rich Markup issue."""
    try:
        console.print(_string, style=style)
    except MarkupError:
        console.print(f"Hit a bracket issue with rich.console printing, defaulting to plain print", style='warn')
        print(_string.plain if isinstance(_string, Text) else _string)


def console_width() -> int:
    """Current width set in `console` object."""
    return console._width or 80  # TODO: wtf?
