from functools import partial
from typing import Any, Callable, List


def escape_yara_pattern(pattern: str) -> str:
    return pattern.replace('/', '\\/')


def line_count(_string: str) -> int:
    return len(_string.split("\n"))


def str_join(_list: List[Any], separator: str, func: Callable = str) -> str:
    """
    Return a comma separated list of strings. If func is provided the output of calling
    it on each element of the list will be used instead of str()
    """
    func = func or str
    return separator.join([func(item) for item in _list])


comma_join = partial(str_join, separator=', ')
newline_join = partial(str_join, separator='\n')
