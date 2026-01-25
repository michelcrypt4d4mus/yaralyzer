import re
from argparse import ArgumentTypeError
from pathlib import Path


class PathArgValidator:
    pass


class PatternsLabelValidator:
    HELP_MSG = "a single digit ('11') or a range ('11-15') (WILL NOT extract the last page)"
    PATTERN_LABEL_REGEX = re.compile(r"^\w+$")

    def __call__(self, value: str):
        if not self.PATTERN_LABEL_REGEX.match(value):
            raise ArgumentTypeError('--patterns-label can only include alphanumeric chars and underscore')

        return value
