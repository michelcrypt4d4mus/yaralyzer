import re
from argparse import ArgumentParser

from yaralyzer.util.helpers.env_helper import log_console
from yaralyzer.util.helpers.string_helper import indented, props_string_indented

SKIP_OPTIONS = ['deprecated', 'help', 'option_strings']
STACK_STRIPPER_REGEX = re.compile(fr"/.*pypoetry/virtualenvs/")


def debug_argparser(parser: ArgumentParser):
    """Debug method to look at argparse internals."""
    from yaralyzer.util.logging import log_console

    for i, action in enumerate((parser)._actions):
        if not action.option_strings:
            continue

        keys = [k for k, v in vars(action).items() if k not in SKIP_OPTIONS and v is not None]
        log_console.print(f"\n{i}: {action.option_strings}", style='cyan', highlight=False)
        log_console.print(props_string_indented(action, keys))


def print_stack():
    import traceback

    for i, stack_obj in enumerate(traceback.extract_stack()):
        line = STACK_STRIPPER_REGEX.sub('', str(stack_obj), 1)
        log_console.print(indented(line, i))
