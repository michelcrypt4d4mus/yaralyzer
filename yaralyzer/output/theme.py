"""
Color theme stuff. [Rich color names](https://rich.readthedocs.io/en/stable/appendix/colors.html)
TODO: interesting colors # row_styles[0] = 'reverse bold on color(144)' <-
"""
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.padding import Padding
from rich.style import Style
from rich.terminal_theme import TerminalTheme
from rich.text import Text
from rich.theme import Theme

# Colors
BYTES = 'color(100) dim'
BYTES_NO_DIM = 'color(100)'
BYTES_BRIGHTER = 'orange1'
BYTES_BRIGHTEST = 'color(220)'
BYTES_HIGHLIGHT = 'color(136)'
ERROR_STYLE = 'error'  # Regex Capture used when extracting quoted chunks of bytes
DARK_GREY = 'color(236)'
GREY = 'color(241)'
GREY_ADDRESS = 'color(238)'
OFF_WHITE = 'color(245)'
PEACH = 'color(215)'

# For the table shown by running --show-colors
MAX_THEME_COL_SIZE = 35

# Theme used by main console
YARALYZER_THEME_DICT = {
    # colors
    'grey': GREY,
    'grey.dark': DARK_GREY,
    'grey.dark_italic': f"{DARK_GREY} italic",
    'grey.darker_italic': 'color(8) dim italic',
    'grey.darkest': 'color(235) dim',
    'grey.light': 'color(248)',
    # bytes
    'bytes': BYTES,
    'bytes.decoded': BYTES_BRIGHTEST,
    'bytes.highlight': BYTES_HIGHLIGHT,
    'bytes.title': BYTES_BRIGHTER,
    # data types
    'number': 'cyan',
    'regex': 'color(218) dim',
    # Decoding attempts
    'decode.no_attempt': "color(60) dim italic",
    'decode.subheading': PEACH,
    'decode.table_header': 'color(101) bold',
    'encoding': 'color(158) underline bold',
    'encoding.header': 'color(158) bold',
    'encoding.language': 'dark_green italic',
    # yara
    'yara.date': 'color(216)',
    'yara.hex': 'color(98)',
    'yara.int': 'color(45)',
    'yara.key': DARK_GREY,
    'yara.match_var': 'color(156) italic',
    'yara.matched_rule': 'on bright_black bold',
    'yara.rules':  Style(color='color(135)', underline=True, bold=True),
    'yara.scanned': Style(color='yellow', underline=True, bold=True),
    'yara.string': 'white',
    'yara.url': 'color(220)',
    # error log events
    ERROR_STYLE: 'bright_red',
    # override defaults
    'repr.path': 'orchid2',
    'repr.filename': 'orchid2',
}

LOG_THEME_DICT = {
    'repr.path': 'dark_orange3',
    'repr.filename': 'dark_orange3',
    'repr.none': 'grey23 italic',
    **YARALYZER_THEME_DICT,
}

LOG_THEME = Theme(LOG_THEME_DICT)
YARALYZER_THEME = Theme(YARALYZER_THEME_DICT)

# Used by --env-vars option
CLI_OPTION_TYPE_STYLES = {
    'Dir': 'violet',
    'Path': 'magenta',
    'Pattern': 'orange1',
    'bool': 'bright_red',
    'int': 'cyan',
    'float': 'blue',
    'str': 'green',
}


# TerminalThemes are used when saving SVGS. This one just swaps white for black in DEFAULT_TERMINAL_THEME
YARALYZER_TERMINAL_THEME = TerminalTheme(
    (0, 0, 0),
    (255, 255, 255),
    [
        (0, 0, 0),
        (128, 0, 0),
        (0, 128, 0),
        (128, 128, 0),
        (0, 0, 128),
        (128, 0, 128),
        (0, 128, 128),
        (192, 192, 192),
    ],
    [
        (128, 128, 128),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (0, 0, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ],
)


def color_theme_grid(styles: dict, app_name: str) -> Padding:
    """Lay out the colors in 'styles' in a grid with a header panel."""
    panel = Panel(f'The {app_name.title()} Color Theme', style='honeydew2', width=60)

    colors = [
        Text('', style='white').append(name[:MAX_THEME_COL_SIZE], style=styles[name]).append(' ')
        for name in sorted(styles.keys())
        if name not in ['reset', 'repr_url']
    ]

    group = Group(panel, Text(''), Columns(colors, column_first=True, equal=True, padding=(0, 5)))
    return Padding(group, (1, 2))


def theme_colors_with_prefix(prefix: str) -> list[Text]:
    """Return a list of (name, style) `Text` objects for all styles in the theme that start with `prefix`."""
    return [Text(k, v) for k, v in YARALYZER_THEME.styles.items() if k.startswith(prefix)]
