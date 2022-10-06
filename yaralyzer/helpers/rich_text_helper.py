"""
Rich colors: https://rich.readthedocs.io/en/stable/appendix/colors.html
TODO: interesting colors # row_styles[0] = 'reverse bold on color(144)' <-
"""
import time
from numbers import Number
from os import path
from typing import List, Union

from rich.columns import Columns
from rich.panel import Panel
from rich.style import Style
from rich.terminal_theme import TerminalTheme
from rich.text import Text

from yaralyzer.output.rich_console import BYTES_BRIGHTEST, console, console_width
from yaralyzer.util.logging import log, log_and_print

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

# Keys are export function names, values are options we always want to use w/that export function
# Not meant for direct access; instead call invoke_rich_export().
_EXPORT_KWARGS = {
    'save_html': {
        'inline_styles': True,
        'theme': YARALYZER_TERMINAL_THEME,
    },
    'save_svg': {
        'theme': YARALYZER_TERMINAL_THEME,
    },
    'save_text': {
        'styles': True,
    },
}


def subheading_width() -> int:
    return int(console_width() * 0.75)


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


def invoke_rich_export(export_method, output_file_basepath) -> str:
    """
    Announce the export, perform the export, announce completion.
    export_method is a Rich.console.save_blah() method, output_file_path is file path w/no extname.
    Returns the path to path data was exported to.
    """
    method_name = export_method.__name__
    extname = 'txt' if method_name == 'save_text' else method_name.split('_')[-1]
    output_file_path = f"{output_file_basepath}.{extname}"

    if method_name not in _EXPORT_KWARGS:
        raise RuntimeError(f"{method_name} is not a valid Rich.console export method!")

    kwargs = _EXPORT_KWARGS[method_name].copy()
    kwargs.update({'clear': False})

    if 'svg' in method_name:
        kwargs.update({'title': path.basename(output_file_path) })

    # Invoke it
    log_and_print(f"Invoking Rich.console.{method_name}('{output_file_path}') with kwargs: '{kwargs}'...")
    start_time = time.perf_counter()
    export_method(output_file_path, **kwargs)
    elapsed_time = time.perf_counter() - start_time
    log_and_print(f"'{output_file_path}' written in {elapsed_time:02f} seconds")
    return output_file_path


def yaralyzer_show_color_theme() -> None:
    """Utility method to show yaralyzer's color theme. Invocable with 'yaralyzer_show_colors'."""
    console.print(Panel('The Yaralyzer Color Theme', style='reverse'))

    colors = [
        prefix_with_plain_text_obj(name[:MAX_THEME_COL_SIZE], style=str(style)).append(' ')
        for name, style in YARALYZER_THEME.styles.items()
        if name not in ['reset', 'repr_url']
    ]

    console.print(Columns(colors, column_first=True, padding=(0,3)))


def dim_if(txt: Union[str, Text], is_dim: bool, style: Union[str, None]=None):
    """Apply 'dim' style if 'is_dim'. 'style' overrides for Text and applies for strings."""
    txt = txt.copy() if isinstance(txt, Text) else Text(txt, style=style or '')

    if is_dim:
        txt.stylize('dim')

    return txt


def print_section_header(headline: str, style=None) -> None:
    style = style or ''
    console.line(2)
    console.print(Panel(headline, style=f"{style} reverse"))
    console.line()


def reverse_color(style: Style) -> Style:
    """Reverses the color for a given style"""
    return Style(color=style.bgcolor, bgcolor=style.color, underline=style.underline, bold=style.bold)
