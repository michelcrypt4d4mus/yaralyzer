import signal
import functools


def timeout(seconds=5, default=None):
    """
    From: https://stackoverflow.com/questions/75928586/how-to-stop-the-execution-of-a-function-in-python-after-a-certain-time

    Example:
        @timeout(seconds=5, default=None)
            def function():
                pass
    """
    def decorator(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):

            def handle_timeout(signum, frame):
                raise TimeoutError()

            signal.signal(signal.SIGALRM, handle_timeout)
            signal.alarm(seconds)
            result = func(*args, **kwargs)
            signal.alarm(0)
            return result

        return wrapper

    return decorator


# import time
# from yaralyzer.util.timeout import timeout

# @timeout(seconds=3, default=None)
# def foo():
#     while True:
#         time.sleep(200)
