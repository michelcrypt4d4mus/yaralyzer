from yaralyzer.helpers.rich_text_helper import print_fatal_error_and_exit


class InvalidArgumentError(ValueError):
    pass


def handle_argument_error(msg: str, e: Exception | None = None, is_used_as_library: bool = False) -> None:
    if is_used_as_library:
        raise e or InvalidArgumentError(msg)
    else:
        print_fatal_error_and_exit(msg, e)
