"""
Rich text decorator for YARA match dicts, which look like this:

{
    'tags': ['foo', 'bar'],
    'matches': True,
    'namespace': 'default',
    'rule': 'my_rule',
    'meta': {},
    'strings': [
        (81L, '$a', 'abc'),
        (141L, '$b', 'def')
    ]
}
"""
import re
from numbers import Number
from typing import Any, Dict

from rich.console import Console, ConsoleOptions, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from yaralyzer.helpers.bytes_helper import clean_byte_string
from yaralyzer.helpers.rich_text_helper import CENTER
from yaralyzer.output.rich_console import console_width, theme_colors_with_prefix
from yaralyzer.util.logging import log

MATCH_PADDING = (0, 0, 0, 1)
URL_REGEX = re.compile('^https?:')
DIGITS_REGEX = re.compile("^\\d+$")
HEX_REGEX = re.compile('^[0-9A-Fa-f]+$')
DATE_REGEX = re.compile('\\d{4}-\\d{2}-\\d{2}')
MATCHER_VAR_REGEX = re.compile('\\$[a-z_]+')

YARA_STRING_STYLES: Dict[re.Pattern, str] = {
    URL_REGEX: 'yara.url',
    DIGITS_REGEX: 'yara.number',
    HEX_REGEX: 'yara.hex',
    DATE_REGEX: 'yara.date',
    MATCHER_VAR_REGEX: 'yara.match_var'
}

RAW_YARA_THEME_COLORS = [color[len('yara') + 1:] for color in theme_colors_with_prefix('yara')]
RAW_YARA_THEME_TXT = Text('\nColor Code: ') + Text(' ').join(RAW_YARA_THEME_COLORS)
RAW_YARA_THEME_TXT.justify = CENTER


class YaraMatch:
    def __init__(self, match: dict, matched_against_bytes_label: Text) -> None:
        self.match = match
        self.rule_name = match['rule']
        self.label = matched_against_bytes_label.copy().append(f" matched rule: '", style='matched_rule')
        self.label.append(self.rule_name, style='on bright_red bold').append("'!", style='siren')

    def __rich_console__(self, _console: Console, options: ConsoleOptions) -> RenderResult:
        """Renders a panel showing the color highlighted raw YARA match info."""
        yield(Text("\n"))
        yield Padding(Panel(self.label, expand=False, style=f"on color(251) reverse"), MATCH_PADDING)
        yield(RAW_YARA_THEME_TXT)
        yield Padding(Panel(_rich_yara_match(self.match)), MATCH_PADDING)


def _rich_yara_match(element: Any, depth: int = 0) -> Text:
    """Mildly painful/hacky way of coloring a yara result hash."""
    indent = Text((depth + 1) * 4 * ' ')
    end_indent = Text(depth * 4 * ' ')

    if isinstance(element, str):
        txt = _yara_string(element)
    elif isinstance(element, bytes):
        txt = Text(clean_byte_string(element), style='bytes')
    elif isinstance(element, Number):
        txt = Text(str(element), style='bright_cyan')
    elif isinstance(element, bool):
        txt = Text(str(element), style='red' if not element else 'green')
    elif isinstance(element, (list, tuple)):
        if len(element) == 0:
            txt = Text('[]', style='white')
        else:
            total_length = sum([len(str(e)) for e in element]) + ((len(element) - 1) * 2) + len(indent) + 2
            elements_txt = [_rich_yara_match(e, depth + 1) for e in element]
            list_txt = Text('[', style='white')

            if total_length > console_width() or len(element) > 3:
                join_txt = Text(f"\n{indent}" )
                list_txt.append(join_txt).append(Text(f",{join_txt}").join(elements_txt))
                list_txt += Text(f'\n{end_indent}]', style='white')
            else:
                list_txt += Text(', ').join(elements_txt) + Text(']')

            return list_txt
    elif isinstance(element, dict):
        element = {k: v for k, v in element.items() if k not in ['matches', 'rule']}

        if len(element) == 0:
            return Text('{}')

        txt = Text('{\n', style='white')

        for i, k in enumerate(element.keys()):
            v = element[k]
            txt += indent + Text(f"{k}: ", style='yara.key') + _rich_yara_match(v, depth + 1)

            if (i + 1) < len(element.keys()):
                txt.append(",\n")
            else:
                txt.append("\n")

        txt += end_indent + Text('}', style='white')
    else:
        log.warning(f"Unknown yara return of type {type(element)}: {element}")
        txt = indent + Text(str(element))

    return txt


def _yara_string(_string: str) -> Text:
    for regex in YARA_STRING_STYLES.keys():
        if regex.match(_string):
            return Text(_string, YARA_STRING_STYLES[regex])

    return Text(_string, style='yara.string')
