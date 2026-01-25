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

# For the table shown by running yaralyzer_show_color_theme
MAX_THEME_COL_SIZE = 35

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
    panel = Panel(f'The {app_name.title()} Color Theme',  style='honeydew2', width=60)

    colors = [
        Text('', style='white').append(name[:MAX_THEME_COL_SIZE], style=style).append(' ')
        for name, style in styles.items()
        if name not in ['reset', 'repr_url']
    ]

    group = Group(panel, Text(''), Columns(colors, column_first=True, padding=(0, 5), equal=True))
    return Padding(group, (1, 2))
