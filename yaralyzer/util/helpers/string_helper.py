"""
Helper methods to work with strings.
"""
import re
from functools import partial
from typing import Any, Callable, List

ANSI_COLOR_CODE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
INDENT_DEPTH = 4
INDENT_SPACES = INDENT_DEPTH * ' '
NUMBER_REGEX = re.compile(r"^[\d.]+$")


def escape_yara_pattern(pattern: str) -> str:
    return pattern.replace('/', '\\/')


def hex_to_string(_string: str) -> str:
    r"""String '0D 0A 25 25 45 4F 46 0D 0A' becomes '\r\n%%EOF\r\n'"""
    return bytearray.fromhex(_string.replace(' ', '')).decode()


def is_number(s: str) -> bool:
    return bool(NUMBER_REGEX.match(s))


def line_count(_string: str) -> int:
    return len(_string.split("\n"))


def props_string(obj: object, keys: list[str] | None = None, joiner: str = ', ') -> str:
    prefix = joiner if '\n' in joiner else ''
    return prefix + joiner.join(props_strings(obj, keys))


def props_strings(obj: object, keys: list[str] | None = None) -> list[str]:
    """Get props of 'obj' in the format ["prop1=5", "prop2='string'"] etc."""
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
