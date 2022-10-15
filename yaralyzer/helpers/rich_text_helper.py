"""
Methods to handle turning various objects into Rich text/table/etc representations
Rich colors: https://rich.readthedocs.io/en/stable/appendix/colors.html
TODO: interesting colors # row_styles[0] = 'reverse bold on color(144)' <-
"""
from typing import Union

from rich.columns import Columns
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

from yaralyzer.output.rich_console import BYTES_BRIGHTEST, BYTES_HIGHLIGHT, YARALYZER_THEME_DICT, console
from yaralyzer.util.logging import log

# String constants
CENTER = 'center'
FOLD = 'fold'
LEFT = 'left'
MIDDLE = 'middle'
RIGHT = 'right'

# Color meter realted constants. Make even sized buckets color coded from blue (cold) to green (go)
METER_COLORS = list(reversed([82, 85, 71, 60, 67, 30, 24, 16]))
METER_INTERVAL = (100 / float(len(METER_COLORS))) + 0.1
# Color meter extra style thresholds (these are assuming a scale of 0-100)
UNDERLINE_CONFIDENCE_THRESHOLD = 90
BOLD_CONFIDENCE_THRESHOLD = 60
DIM_COUNTRY_THRESHOLD = 25

# For the table shown by running yaralyzer_show_color_theme
MAX_THEME_COL_SIZE = 35

# Text object defaults mostly for table entries
NO_DECODING_ERRORS_MSG = Text('No', style='green4 dim')
DECODING_ERRORS_MSG = Text('Yes', style='dark_red dim')


def na_txt(style: Union[str, Style] = 'white'):
    return Text('N/A', style=style)


def prefix_with_plain_text_obj(_str: str, style: str, root_style=None) -> Text:
    """Sometimes you need a Text() object to start plain lest the underline or whatever last forever"""
    return Text('', style=root_style or 'white') + Text(_str, style)


def meter_style(meter_pct):
    """For coloring numbers between 0 and 100 (AKA pcts). Closer to 100 means greener, closer to 0.0 means bluer"""
    if meter_pct > 100 or meter_pct < 0:
        log.warning(f"Invalid meter_pct: {meter_pct}")

    color_number = METER_COLORS[int(meter_pct / METER_INTERVAL)]
    style = f"color({color_number})"

    if meter_pct > BOLD_CONFIDENCE_THRESHOLD:
        style += ' bold'
    if meter_pct > UNDERLINE_CONFIDENCE_THRESHOLD:
        style += ' underline'

    return style


def unprintable_byte_to_text(code: str, style='') -> Text:
    """Used with ASCII escape codes and the like, gives colored results like '[NBSP]'."""
    style = BYTES_HIGHLIGHT if style == BYTES_BRIGHTEST else style
    txt = Text('[', style=style)
    txt.append(code.upper(), style=f"{style} italic dim")
    txt.append(Text(']', style=style))
    return txt


def dim_if(txt: Union[str, Text], is_dim: bool, style: Union[str, None]=None):
    """Apply 'dim' style if 'is_dim'. 'style' overrides for Text and applies for strings."""
    txt = txt.copy() if isinstance(txt, Text) else Text(txt, style=style or '')

    if is_dim:
        txt.stylize('dim')

    return txt


def reverse_color(style: Style) -> Style:
    """Reverses the color for a given style"""
    return Style(color=style.bgcolor, bgcolor=style.color, underline=style.underline, bold=style.bold)


def yaralyzer_show_color_theme() -> None:
    """Script method to show yaralyzer's color theme. Invocable with 'yaralyzer_show_colors'."""
    show_color_theme(YARALYZER_THEME_DICT)


def show_color_theme(styles: dict) -> None:
    """Print all colors in 'styles' to screen in a grid"""
    console.print(Panel('The Yaralyzer Color Theme', style='reverse'))

    colors = [
        prefix_with_plain_text_obj(name[:MAX_THEME_COL_SIZE], style=str(style)).append(' ')
        for name, style in styles.items()
        if name not in ['reset', 'repr_url']
    ]

    console.print(Columns(colors, column_first=True, padding=(0,5), equal=True))


def size_text(num_bytes: int) -> Text:
    """Convert a number of bytes into (e.g.) 54,213 bytes (52 KB)"""
    kb_txt = prefix_with_plain_text_obj("{:,.1f}".format(num_bytes / 1024), style='bright_cyan', root_style='white')
    kb_txt.append(' kb ')
    bytes_txt = Text('(', 'white') + size_in_bytes_text(num_bytes) + Text(')')
    return kb_txt + bytes_txt


def size_in_bytes_text(num_bytes: int) -> Text:
    return  Text(f"{num_bytes:,d}", 'number').append(' bytes', style='white')
