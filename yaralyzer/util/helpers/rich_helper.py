"""
Methods to handle turning various objects into Rich text/table/etc representations.
"""
from typing import List, Optional, Union

from rich import box
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

from yaralyzer.output.theme import BYTES_DECODED, BYTES_HIGHLIGHT
from yaralyzer.output.console import console
from yaralyzer.util.helpers.env_helper import is_invoked_by_pytest
from yaralyzer.util.logging import log

# Color meter realted constants. Make even sized buckets color coded from blue (cold) to green (go)
METER_COLORS = list(reversed([82, 85, 71, 60, 67, 30, 24, 16]))
METER_INTERVAL = (100 / float(len(METER_COLORS))) + 0.1
# Color meter extra style thresholds (these are assuming a scale of 0-100)
BOLD_CONFIDENCE_THRESHOLD = 60
UNDERLINE_CONFIDENCE_THRESHOLD = 90

# Global default Table options. Default is box.HEAVY_HEAD but that yields different results on windows.
if is_invoked_by_pytest():
    DEFAULT_TABLE_OPTIONS = {'box': box.SQUARE}
else:
    DEFAULT_TABLE_OPTIONS = {'box': box.HEAVY_HEAD}


def dim_if(txt: Union[str, Text], is_dim: bool):
    """Apply 'dim' style if 'is_dim'. 'style' overrides for Text and applies for strings."""
    txt = txt.copy() if isinstance(txt, Text) else Text(txt)

    if is_dim:
        txt.stylize('dim')

    return txt


def meter_style(meter_pct: float | int) -> str:
    """For coloring numbers between 0 and 100 (AKA pcts). Closer to 100 means greener, closer to 0.0 means bluer."""
    if meter_pct > 100 or meter_pct < 0:
        log.warning(f"Invalid meter_pct: {meter_pct}")

    color_number = METER_COLORS[int(meter_pct / METER_INTERVAL)]
    style = f"color({color_number})"

    if meter_pct > BOLD_CONFIDENCE_THRESHOLD:
        style += ' bold'
    if meter_pct > UNDERLINE_CONFIDENCE_THRESHOLD:
        style += ' underline'

    return style


def na_txt(style: Union[str, Style] = 'white'):
    """Standard N/A text for tables and such."""
    return Text('N/A', style=style)


def newline_join(texts: List[Text]) -> Text:
    """Join a list of Text objects with newlines between them."""
    return Text("\n").join(texts)


def prefix_with_style(_str: str, style: str, root_style: Optional[Union[Style, str]] = None) -> Text:
    """Sometimes you need a Text() object to start plain lest the underline or whatever last forever."""
    return Text('', style=root_style or 'white') + Text(_str, style)


def print_header_panel(headline: str, style: str, expand: bool = True, padding: tuple | None = None) -> None:
    """
    Print a headline inside a styled Rich `Panel` to the console.

    Args:
        headline (str): The text to display as the panel's headline.
        style (str): The style to apply to the panel (e.g., color, bold, reverse).
        expand (bool, optional): Whether the panel should expand to the full console width. Defaults to `True`.
        padding (tuple, optional): Padding around the panel content (top/bottom, left/right). Defaults to `(0, 2)`.
    """
    console.print(Panel(
        headline,
        expand=expand,
        padding=padding or (0, 2),
        style=style,
        **DEFAULT_TABLE_OPTIONS
    ))


def reverse_color(style: Style) -> Style:
    """Reverses the color for a given style."""
    return Style(color=style.bgcolor, bgcolor=style.color, underline=style.underline, bold=style.bold)


def size_in_bytes_text(num_bytes: int) -> Text:
    return Text(f"{num_bytes:,d}", 'number').append(' bytes', style='white')


def size_text(num_bytes: int) -> Text:
    """Convert a number of bytes into (e.g.) '54,213 bytes (52 KB)'."""
    kb_txt = prefix_with_style("{:,.1f}".format(num_bytes / 1024), style='bright_cyan', root_style='white')
    kb_txt.append(' kb ')
    bytes_txt = Text('(', 'white') + size_in_bytes_text(num_bytes) + Text(')')
    return kb_txt + bytes_txt


def unprintable_byte_to_text(code: str, style: str = '') -> Text:
    """Used with ASCII escape codes and the like, gives colored results like '[NBSP]'."""
    style = BYTES_HIGHLIGHT if style == BYTES_DECODED else style
    txt = Text('[', style=style)
    txt.append(code.upper(), style=f"{style} italic dim")
    txt.append(Text(']', style=style))
    return txt
