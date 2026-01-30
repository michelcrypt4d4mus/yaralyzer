import functools
import signal

from yaralyzer.util.helpers.env_helper import is_windows


def timeout(seconds=5, default=None):
    """
    From:
    https://stackoverflow.com/questions/75928586/how-to-stop-the-execution-of-a-function-in-python-after-a-certain-time

    Example:
        @timeout(seconds=5, default=None)
        def function():
            sleep(6000)
    """
    def decorator(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):

            def handle_timeout(signum, frame):
                raise TimeoutError(f"Timed out after {seconds} seconds.")

            # Windows doesn't support SIGALRM
            if not is_windows():
                signal.signal(signal.SIGALRM, handle_timeout)
                signal.alarm(seconds)

            result = func(*args, **kwargs)

            if not is_windows():
                signal.alarm(0)
            return result

        return wrapper

    return decorator
