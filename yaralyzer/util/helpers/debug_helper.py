import re
from os import getlogin

from yaralyzer.util.helpers.env_helper import stderr_console
from yaralyzer.util.helpers.string_helper import indented

STACK_STRIPPER_REGEX = re.compile(fr"/.*{getlogin()}.*pypoetry/virtualenvs/")


def print_stack():
    import traceback

    for i, stack_obj in enumerate(traceback.extract_stack()):
        line = STACK_STRIPPER_REGEX.sub('', str(stack_obj), 1)
        stderr_console.print(indented(line, i))
