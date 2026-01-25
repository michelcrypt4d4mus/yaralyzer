"""
Validators for command line arguments.
"""
import re
from abc import ABC
from argparse import ArgumentTypeError
from pathlib import Path

import yara

from yaralyzer.yara.yara_rule_builder import PATTERN_TYPES, build_yara_rule


class OptionValidator(ABC):
    """
    Base class for CLI options validators that needs to be in its own file because of circular
    dependency issues.
    """
    def arg_type_str(self) -> str:
        return type(self).__name__.removesuffix('Validator')


class DirValidator(OptionValidator):
    def __call__(self, value: str) -> Path:
        dir = Path(value)

        if not dir.exists():
            raise ArgumentTypeError(f"'{dir}' is not a directory that exists")
        elif not dir.is_dir():
            raise ArgumentTypeError(f"'{dir}' is a file not directory")

        return dir


class PathValidator(OptionValidator):
    def __call__(self, value: str) -> Path:
        file_path = Path(value)

        if not file_path.exists():
            raise ArgumentTypeError(f"'{file_path}' is not a file that exists")

        return file_path


class PatternsLabelValidator(OptionValidator):
    PATTERN_LABEL_REGEX = re.compile(r"^\w+$")

    def arg_type_str(self) -> str:
        return 'str'

    def __call__(self, value: str) -> str:
        if not self.PATTERN_LABEL_REGEX.match(value):
            raise ArgumentTypeError('--patterns-label can only include alphanumeric and underscore')

        return value


class YaraRegexValidator(OptionValidator):
    def arg_type_str(self) -> str:
        return 'Pattern'

    def __call__(self, value: str) -> str:
        compiled_rule = None
        compilation_error = None

        if '\n' in value:
            raise ArgumentTypeError("Use \\n if you want newlines in your regex")
        elif len(value) > 1 and value[0] == '/' and value[-1] == '/':
            print(f"(hint: you don't need to surround your regex with front slashes)")
            value = value[1:-1]

        # Since we can't know if it's a hex or regex pattern yet, try both and accept if either works.
        for pattern_type in PATTERN_TYPES:
            try:
                compiled_rule = build_yara_rule(value, pattern_type=pattern_type)
            except yara.SyntaxError as e:
                compilation_error = e
            except Exception as e:
                compilation_error = e

        if compiled_rule:
            return value
        else:
            raise ArgumentTypeError(f"SyntaxError: your pattern is invalid ({compilation_error})")
