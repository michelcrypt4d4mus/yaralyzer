"""
Helper methods to work with strings.
"""
import re
from functools import partial
from typing import Any, Callable, List

from yaralyzer.util.constants import LOG_LEVELS

ANSI_COLOR_CODE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
INDENT_DEPTH = 4
INDENT_SPACES = INDENT_DEPTH * ' '
INDENTED_JOINER = ',\n' + INDENT_SPACES
NUMBER_REGEX = re.compile(r"^[\d.]+$")
NON_WORD_CHAR_REGEX = re.compile(r"[^\w]")

is_falsey = lambda s: str(s).lower() in ['', '0', 'false', 'no']
is_truthy = lambda s: s.lower() in ['1', 'true', 'yes']


def escape_yara_pattern(pattern: str) -> str:
    return pattern.replace('/', '\\/')


def hex_to_string(_string: str) -> str:
    r"""String '0D 0A 25 25 45 4F 46 0D 0A' becomes '\r\n%%EOF\r\n'"""
    return bytearray.fromhex(_string.replace(' ', '')).decode()


def indented(s: str, spaces: int = 4, prefix: str = '') -> str:
    indent = ' ' * spaces
    indent += prefix
    return indent + f"\n{indent}".join(s.split('\n'))


def indented_paragraph(s: str, spaces: int = 4, prefix: str = '') -> str:
    return '\n'.join([indented(line) for line in s.split('\n')])


def is_number(s: str) -> bool:
    return bool(NUMBER_REGEX.match(s))


def line_count(_string: str) -> int:
    return len(_string.split("\n"))


def log_level_for(value: str | int) -> int:
    """Accepts log level strings like WARNING, INFO, etc. as well as custom `TRACE` level."""
    if isinstance(value, int):
        return value
    elif re.match(r"\d+", value):
        return int(value)
    elif value in LOG_LEVELS:
        return LOG_LEVELS[value]
    else:
        raise ValueError(f"'{value}' is not a valid log level!")


def props_string(obj: object, keys: list[str] | None = None, joiner: str = ', ') -> str:
    """Generate a string that shows an object's properties, similar to standard repr()."""
    prefix = joiner if '\n' in joiner else ''
    return prefix + joiner.join(props_strings(obj, keys))


def props_string_indented(obj: object, keys: list[str] | None = None) -> str:
    return props_string(obj, keys, INDENTED_JOINER)


def props_strings(obj: object, keys: list[str] | None = None) -> list[str]:
    """Get props of 'obj' in the format ["prop1=5", "prop2='string'"] etc. (for repr(), mostly)."""
    props = []

    for k in (keys or [k for k in vars(obj).keys()]):
        value = getattr(obj, k)
        value = f"'{value}'" if isinstance(value, str) else value
        props.append(f"{k}={value}")

    return props


def str_join(_list: List[Any], separator: str, func: Callable = str) -> str:
    """
    Return a comma separated list of strings. If func is provided the output of calling
    it on each element of the list will be used instead of str()
    """
    func = func or str
    return separator.join([func(item) for item in _list])


def strip_ansi_colors(ansi_str: str) -> str:
    """Remove ANSI color codes from a string."""
    return ANSI_COLOR_CODE_REGEX.sub('', ansi_str).strip()


comma_join = partial(str_join, separator=', ')
newline_join = partial(str_join, separator='\n')
