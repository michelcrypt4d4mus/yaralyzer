import logging
from argparse import ArgumentParser, Namespace
from os import environ
from typing import Any, List

YARALYZE = 'yaralyze'
YARALYZER = f"{YARALYZE}r".upper()
PYTEST_FLAG = 'INVOKED_BY_PYTEST'

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE


def config_var_name(env_var: str) -> str:
    """
    Get the name of env_var and strip off 'YARALYZER_':

    SURROUNDING_BYTES_ENV_VAR = 'YARALYZER_SURROUNDING_BYTES'
    config_var_name(SURROUNDING_BYTES_ENV_VAR) => 'SURROUNDING_BYTES'
    """
    env_var = env_var.removeprefix("YARALYZER_")
    return f'{env_var=}'.partition('=')[0]


def is_env_var_set_and_not_false(var_name):
    """Returns True if var_name is not empty and set to anything other than 'false' (capitalization agnostic)"""
    if var_name in environ:
        var_value = environ[var_name]
        return var_value is not None and len(var_value) > 0 and var_value.lower() != 'false'
    else:
        return False


def is_invoked_by_pytest():
    """Return true if pytest is running"""
    return is_env_var_set_and_not_false(PYTEST_FLAG)


class YaralyzerConfig:
    # Passed through to yara.set_config()
    DEFAULT_MAX_MATCH_LENGTH = 100 * KILOBYTE
    DEFAULT_YARA_STACK_SIZE = 2 * 65536

    # Skip decoding binary matches under/over these lengths
    DEFAULT_MIN_DECODE_LENGTH = 1
    DEFAULT_MAX_DECODE_LENGTH = 256

    # chardet.detect() related
    DEFAULT_MIN_CHARDET_BYTES = 9
    DEFAULT_MIN_CHARDET_CONFIDENCE = 2.0  # TODO: unused

    # Number of bytes to show before/after byte previews and decodes. Configured by command line or env var
    DEFAULT_SURROUNDING_BYTES = 64

    LOG_DIR_ENV_VAR = 'YARALYZER_LOG_DIR'
    LOG_DIR = environ.get(LOG_DIR_ENV_VAR)
    LOG_LEVEL_ENV_VAR = f"{YARALYZER}_LOG_LEVEL"
    LOG_LEVEL = logging.getLevelName(environ.get(LOG_LEVEL_ENV_VAR, 'WARN'))

    # MAX_MATCH_LENGTH = int(environ.get(MAX_MATCH_LENGTH_ENV_VAR, DEFAULT_MAX_MATCH_LENGTH))
    # YARA_STACK_SIZE = int(environ.get(YARA_STACK_SIZE_ENV_VAR, DEFAULT_YARA_STACK_SIZE))

    # MIN_BYTES_FOR_ENCODING_DETECTION = int(environ.get(
    #     MIN_BYTES_TO_DETECT_ENCODING_ENV_VAR,
    #     DEFAULT_MIN_BYTES_TO_DETECT_ENCODING
    # ))

    # MIN_DECODE_LENGTH = int(environ.get(MIN_DECODE_LENGTH_ENV_VAR, DEFAULT_MIN_DECODE_LENGTH))
    # MAX_DECODE_LENGTH = int(environ.get(MAX_DECODE_LENGTH_ENV_VAR, DEFAULT_MAX_DECODE_LENGTH))
    # NUM_SURROUNDING_BYTES = int(environ.get(SURROUNDING_BYTES_ENV_VAR, DEFAULT_SURROUNDING_BYTES))

    # SUPPRESS_CHARDET_OUTPUT = is_env_var_set_and_not_false(SUPPRESS_CHARDET_TABLE_ENV_VAR)
    # SUPPRESS_DECODES_TABLE = is_env_var_set_and_not_false(SUPPRESS_DECODES_TABLE_ENV_VAR)
    # SUPPRESS_DECODING_ATTEMPTS = is_env_var_set_and_not_false(SUPPRESS_DECODING_ATTEMPTS_ENV_VAR)
    # MIN_CHARDET_CONFIDENCE = float(environ.get(MIN_CHARDET_CONFIDENCE_ENV_VAR, DEFAULT_MIN_CHARDET_CONFIDENCE))

    HIGHLIGHT_STYLE = 'orange1'

    ONLY_CLI_ARGS = [
        'debug',
        'help',
        'hex_patterns',
        'interact',
        'patterns_label',
        'regex_patterns',
        'regex_modifier',
        'version'
    ]

    @classmethod
    def set_argument_parser(cls, parser):
        cls._argument_parser: ArgumentParser = parser
        cls._argparse_keys: List[str] = sorted([action.dest for action in parser._actions])

    @classmethod
    def set_args(cls, args: Namespace) -> None:
        cls.args = args

        for option in cls._argparse_keys:
            if option.startswith('export') or option in cls.ONLY_CLI_ARGS:
                continue

            arg_value = vars(args)[option]
            env_var = f"{YARALYZER}_{option.upper()}"
            env_value = environ.get(env_var)
            default_value = cls.get_default_arg(option)

            if isinstance(type(arg_value), bool):
                setattr(args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                # Check against defaults to avoid overriding env var configured optoins
                if arg_value == default_value and env_value is not None:
                    setattr(args, option, int(env_value) or arg_value)  # TODO: float args not handled
            else:
                setattr(args, option, arg_value or env_value)

    @classmethod
    def set_default_args(cls):
        cls.set_args(cls._argument_parser.parse_args(['dummy']))

    @classmethod
    def get_default_arg(cls, arg: str) -> Any:
        default_var = f"DEFAULT_{arg.upper()}"
        return vars(cls).get(default_var)
