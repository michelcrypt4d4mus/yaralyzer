from argparse import ArgumentTypeError
from rich.padding import Padding
from rich.text import Text

from yaralyzer.util.helpers.env_helper import is_invoked_by_pytest
from yaralyzer.util.logging import highlighter, log_console


class InvalidArgumentError(ArgumentTypeError):
    pass


def handle_argument_error(msg: str, e: Exception | None = None, is_standalone_mode: bool = False) -> None:
    """Standalone mode means in a situation where the `yaralyze` command is being run."""
    if is_standalone_mode and not is_invoked_by_pytest():
        print_fatal_error_and_exit(msg, e)
    else:
        raise e or InvalidArgumentError(msg)


def print_fatal_error(msg: str | Text | None, e: Exception | None = None) -> None:
    """
    Print a fatal error message

    Args:
        msg (str): The error message to display.
        e (Exception | None): The exception that caused the error, if any.
    """
    txt = Text('').append('(ERROR)', style='bright_red bold').append(" ")

    if msg:
        msg = msg if isinstance(msg, Text) else Text(msg, style='honeydew2')
        txt.append(highlighter(msg))

    if e:
        txt.append(f"\n(Caused by {type(e).__name__}: {e})", style='dim')

    log_console.print(Padding(txt, (1, 0, 0, 0)))


def print_fatal_error_and_exit(msg: str, e: Exception | None = None, exit_code: int = 1) -> None:
    """Print an error message and exit with code 'exit_code'."""
    print_fatal_error(msg, e)
    exit(exit_code)
