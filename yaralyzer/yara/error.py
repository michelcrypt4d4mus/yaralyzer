"""
Handling of internal YARA errors.
"""
import re

import yara

INTERNAL_ERROR_REGEX = re.compile(r"internal error: (\d+)$")
YARA_ERRORS_REPO_PATH = 'master/libyara/include/yara/error.h'
YARA_ERRORS_RAW_URL = f"https://raw.githubusercontent.com/VirusTotal/yara/refs/heads/{YARA_ERRORS_REPO_PATH}"
YARA_ERRORS_URL = f"https://github.com/VirusTotal/yara/blob/{YARA_ERRORS_REPO_PATH}"

# Extracted from YARA_ERRORS_RAW_URL
YARA_ERROR_CODES = {
    0: 'SUCCESS',
    1: 'INSUFFICIENT_MEMORY',
    2: 'COULD_NOT_ATTACH_TO_PROCESS',
    3: 'COULD_NOT_OPEN_FILE',
    4: 'COULD_NOT_MAP_FILE',
    6: 'INVALID_FILE',
    7: 'CORRUPT_FILE',
    8: 'UNSUPPORTED_FILE_VERSION',
    9: 'INVALID_REGULAR_EXPRESSION',
    10: 'INVALID_HEX_STRING',
    11: 'SYNTAX_ERROR',
    12: 'LOOP_NESTING_LIMIT_EXCEEDED',
    13: 'DUPLICATED_LOOP_IDENTIFIER',
    14: 'DUPLICATED_IDENTIFIER',
    15: 'DUPLICATED_TAG_IDENTIFIER',
    16: 'DUPLICATED_META_IDENTIFIER',
    17: 'DUPLICATED_STRING_IDENTIFIER',
    18: 'UNREFERENCED_STRING',
    19: 'UNDEFINED_STRING',
    20: 'UNDEFINED_IDENTIFIER',
    21: 'MISPLACED_ANONYMOUS_STRING',
    22: 'INCLUDES_CIRCULAR_REFERENCE',
    23: 'INCLUDE_DEPTH_EXCEEDED',
    24: 'WRONG_TYPE',
    25: 'EXEC_STACK_OVERFLOW',
    26: 'SCAN_TIMEOUT',
    27: 'TOO_MANY_SCAN_THREADS',
    28: 'CALLBACK_ERROR',
    29: 'INVALID_ARGUMENT',
    30: 'TOO_MANY_MATCHES',
    31: 'INTERNAL_FATAL_ERROR',
    32: 'NESTED_FOR_OF_LOOP',
    33: 'INVALID_FIELD_NAME',
    34: 'UNKNOWN_MODULE',
    35: 'NOT_A_STRUCTURE',
    36: 'NOT_INDEXABLE',
    37: 'NOT_A_FUNCTION',
    38: 'INVALID_FORMAT',
    39: 'TOO_MANY_ARGUMENTS',
    40: 'WRONG_ARGUMENTS',
    41: 'WRONG_RETURN_TYPE',
    42: 'DUPLICATED_STRUCTURE_MEMBER',
    43: 'EMPTY_STRING',
    44: 'DIVISION_BY_ZERO',
    45: 'REGULAR_EXPRESSION_TOO_LARGE',
    46: 'TOO_MANY_RE_FIBERS',
    47: 'COULD_NOT_READ_PROCESS_MEMORY',
    48: 'INVALID_EXTERNAL_VARIABLE_TYPE',
    49: 'REGULAR_EXPRESSION_TOO_COMPLEX',
    50: 'INVALID_MODULE_NAME',
    51: 'TOO_MANY_STRINGS',
    52: 'INTEGER_OVERFLOW',
    53: 'CALLBACK_REQUIRED',
    54: 'INVALID_OPERAND',
    55: 'COULD_NOT_READ_FILE',
    56: 'DUPLICATED_EXTERNAL_VARIABLE',
    57: 'INVALID_MODULE_DATA',
    58: 'WRITING_FILE',
    59: 'INVALID_MODIFIER',
    60: 'DUPLICATED_MODIFIER',
    61: 'BLOCK_NOT_READY',
    62: 'INVALID_PERCENTAGE',
    63: 'IDENTIFIER_MATCHES_WILDCARD',
    64: 'INVALID_VALUE',
    65: 'TOO_SLOW_SCANNING',
    66: 'UNKNOWN_ESCAPE_SEQUENCE',
}


def yara_error_msg(exception: yara.Error) -> str:
    """Turn a mysterious YARA error code number into a human readable string."""
    if (internal_error_match := INTERNAL_ERROR_REGEX.search(str(exception))):
        error_code = int(internal_error_match.group(1))
        msg = f"Internal YARA error! (code: {error_code}, type: {YARA_ERROR_CODES[error_code]})"

        if error_code == 25:
            msg += "\n\nRunning with a larger --yara-stack-size may solve this problem."

        return msg
    else:
        return f"YARA error: {exception}"
