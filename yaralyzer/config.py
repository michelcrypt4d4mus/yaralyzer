import logging
from os import environ

YARALYZE = 'yaralyze'
PYTEST_FLAG = 'INVOKED_BY_PYTEST'

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE

# Configuring YARALYZER_LOG_DIR has side effects; see .yaralyzer.example in repo for specifics.
LOG_LEVEL_ENV_VAR = 'YARALYZER_LOG_LEVEL'
LOG_DIR_ENV_VAR = 'YARALYZER_LOG_DIR'

# Output suppression
SUPPRESS_CHARDET_TABLE_ENV_VAR = 'YARALYZER_SUPPRESS_CHARDET_TABLE'
SUPPRESS_DECODES_ENV_VAR = 'YARALYZER_SUPPRESS_DECODE'

# Passed through to yara.set_config()
DEFAULT_MAX_MATCH_LENGTH = 100 * KILOBYTE
DEFAULT_YARA_STACK_SIZE = 2 * 65536
MAX_MATCH_LENGTH_ENV_VAR = 'YARALYZER_MAX_MATCH_LENGTH'
YARA_STACK_SIZE_ENV_VAR = 'YARALYZER_YARA_STACK_SIZE'

# Skip decoding binary matches over this length
DEFAULT_MIN_DECODE_LENGTH = 1
DEFAULT_MAX_DECODE_LENGTH = 256
MIN_DECODE_LENGTH_ENV_VAR = 'YARALYZER_MIN_DECODE_LENGTH'
MAX_DECODE_LENGTH_ENV_VAR = 'YARALYZER_MAX_DECODE_LENGTH'

# chardet.detect() related
DEFAULT_MIN_BYTES_TO_DETECT_ENCODING = 9
MIN_BYTES_TO_DETECT_ENCODING_ENV_VAR = 'YARALYZER_MIN_BYTES_TO_DETECT_ENCODING'
DEFAULT_MIN_CHARDET_CONFIDENCE = 2.0
MIN_CHARDET_CONFIDENCE_ENV_VAR = 'YARALYZER_MIN_CHARDET_CONFIDENCE'

# Number of bytes to show before/after byte previews and decodes. Configured by command line or env var
DEFAULT_SURROUNDING_BYTES = 64
SURROUNDING_BYTES_ENV_VAR = 'YARALYZER_SURROUNDING_BYTES'


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
    LOG_DIR = environ.get(LOG_DIR_ENV_VAR)
    LOG_LEVEL = logging.getLevelName(environ.get(LOG_LEVEL_ENV_VAR, 'WARN'))

    MAX_MATCH_LENGTH = int(environ.get(MAX_MATCH_LENGTH_ENV_VAR, DEFAULT_MAX_MATCH_LENGTH))
    YARA_STACK_SIZE = int(environ.get(YARA_STACK_SIZE_ENV_VAR, DEFAULT_YARA_STACK_SIZE))

    MIN_BYTES_FOR_ENCODING_DETECTION = int(environ.get(
        MIN_BYTES_TO_DETECT_ENCODING_ENV_VAR,
        DEFAULT_MIN_BYTES_TO_DETECT_ENCODING
    ))

    MIN_DECODE_LENGTH = int(environ.get(MIN_DECODE_LENGTH_ENV_VAR, DEFAULT_MIN_DECODE_LENGTH))
    MAX_DECODE_LENGTH = int(environ.get(MAX_DECODE_LENGTH_ENV_VAR, DEFAULT_MAX_DECODE_LENGTH))
    NUM_SURROUNDING_BYTES = int(environ.get(SURROUNDING_BYTES_ENV_VAR, DEFAULT_SURROUNDING_BYTES))

    SUPPRESS_CHARDET_OUTPUT = is_env_var_set_and_not_false(SUPPRESS_CHARDET_TABLE_ENV_VAR)
    SUPPRESS_DECODES = is_env_var_set_and_not_false(SUPPRESS_DECODES_ENV_VAR)
    MIN_CHARDET_CONFIDENCE = float(environ.get(MIN_CHARDET_CONFIDENCE_ENV_VAR, DEFAULT_MIN_CHARDET_CONFIDENCE))

    HIGHLIGHT_STYLE = 'orange1'
