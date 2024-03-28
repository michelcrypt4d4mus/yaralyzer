"""
Helper methods to work with strings.
"""
from functools import partial
from typing import Any, Callable, List

INDENT_DEPTH = 4
INDENT_SPACES = INDENT_DEPTH * ' '


def escape_yara_pattern(pattern: str) -> str:
    return pattern.replace('/', '\\/')


def line_count(_string: str) -> int:
    return len(_string.split("\n"))


def hex_to_string(_string: str) -> str:
    """String '0D 0A 25 25 45 4F 46 0D 0A' becomes '\r\n%%EOF\r\n'"""
    return bytearray.fromhex(_string.replace(' ', '')).decode()


def str_join(_list: List[Any], separator: str, func: Callable = str) -> str:
    """
    Return a comma separated list of strings. If func is provided the output of calling
    it on each element of the list will be used instead of str()
    """
    func = func or str
    return separator.join([func(item) for item in _list])


comma_join = partial(str_join, separator=', ')
newline_join = partial(str_join, separator='\n')
