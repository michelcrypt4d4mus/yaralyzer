"""
Holds the rich.Console instance that controls the stdout printing and file export.
"""
from typing import List

from rich.console import Console
from rich.errors import MarkupError
from rich.style import Style
from rich.text import Text
from rich.theme import Theme

from yaralyzer.util.helpers.env_helper import DEFAULT_CONSOLE_KWARGS

# Colors
ALERT_STYLE = 'error'  # Regex Capture used when extracting quoted chunks of bytes
BYTES = 'color(100) dim'
BYTES_NO_DIM = 'color(100)'
BYTES_BRIGHTEST = 'color(220)'
BYTES_BRIGHTER = 'orange1'
BYTES_HIGHLIGHT = 'color(136)'
DANGER_HEADER = 'color(88) on white'  # Red
DEFAULT_HIGHLIGHT_STYLE = 'orange1'
DARK_GREY = 'color(236)'
GREY = 'color(241)'
GREY_ADDRESS = 'color(238)'
PEACH = 'color(215)'

# Theme used by main console
YARALYZER_THEME_DICT = {
    # colors
    'dark_orange': 'color(58)',
    'grey': GREY,
    'grey.dark': DARK_GREY,
    'grey.dark_italic': f"{DARK_GREY} italic",
    'grey.darker_italic': 'color(8) dim italic',
    'grey.darkest': 'color(235) dim',
    'grey.light': 'color(248)',
    'off_white': 'color(245)',
    'zero_bytes': 'color(20)',
    # data types
    'encoding': 'color(158) underline bold',
    'encoding.header': 'color(158) bold',
    'encoding.language': 'dark_green italic',
    'number': 'cyan',
    'regex': 'color(218) dim',
    'no_attempt': "color(60) dim italic",
    # design elements
    'decode.section_header': 'color(100) reverse',
    'decode.subheading': PEACH,
    'decode.subheading_2': 'color(215) dim italic',
    'decode.table_header': 'color(101) bold',
    'headline': 'bold white underline',
    # bytes
    'ascii': 'color(58)',
    'ascii_unprintable': 'color(131)',
    'bytes': BYTES,
    'bytes.title_dim': 'orange1 dim',
    'bytes.title': BYTES_BRIGHTER,
    'bytes.decoded': BYTES_BRIGHTEST,
    # yara
    'matched_rule': 'on bright_black bold',
    'yara.key': DARK_GREY,
    'yara.match_var': 'color(156) italic',
    'yara.string': 'white',
    'yara.date': 'color(216)',
    'yara.url': 'color(220)',
    'yara.int': 'color(45)',
    'yara.hex': 'color(98)',
    'yara.scanned': Style(color='yellow', underline=True, bold=True),
    'yara.rules':  Style(color='color(135)', underline=True, bold=True),
    # error log events
    'error': 'bright_red',
}

YARALYZER_THEME = Theme(YARALYZER_THEME_DICT)

console = Console(highlight=False, theme=YARALYZER_THEME, **DEFAULT_CONSOLE_KWARGS)


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


def theme_colors_with_prefix(prefix: str) -> List[Text]:
    """Return a list of (name, style) `Text` objects for all styles in the theme that start with `prefix`."""
    return [Text(k, v) for k, v in YARALYZER_THEME.styles.items() if k.startswith(prefix)]
