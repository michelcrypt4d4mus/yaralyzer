from argparse import Namespace
import logging

from os import environ
from typing import List

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
        'hex_patterns',
        'interact',
        'patterns_label',
        'regex_patterns',
        'regex_modifier',
        'version'
    ]

    _argparse_keys: List[str] = []

    @classmethod
    def set_args(cls, args: Namespace) -> None:
        cls.args = args

        for option in cls._argparse_keys:
            if option.startswith('export') or option in cls.ONLY_CLI_ARGS:
                continue

            arg_value = vars(args)[option]
            default_var = f"DEFAULT_{option.upper()}"
            env_var = f"{YARALYZER}_{option.upper()}"
            env_value = environ.get(env_var)

            if isinstance(type(arg_value), bool):
                setattr(args, option, arg_value or is_env_var_set_and_not_false(env_var))
            elif isinstance(arg_value, (int, float)):
                if default_var in vars(cls):
                    default_value = vars(cls)[default_var]
                    print(f" DEFAULT for {option}: {default_value}")
                else:
                    default_value = None

                # Check against defaults to avoid overriding env var configured optoins
                if default_value == arg_value and env_value is not None:
                    setattr(args, option, int(env_value) or arg_value)  # TODO: float args not handled
            else:
                setattr(args, option, arg_value or env_value)

    @classmethod
    def set_default_args(cls):
        defaults = {k.removeprefix('DEFAULT_').lower(): v for k, v in vars(cls).items() if k.startswith('DEFAULT_')}
        _args = Namespace(**defaults)
        cls.set_args(_args)



        # env_var_args = {
        #     f"{YARALYZER}_{option.upper()}": vars(args)[option]

        #     if not (option.startswith('export') or option in cls.ONLY_CLI_ARGS)
        # }

        # for env_var, value in env_var_args:
        #     print(f"{env_var} => {environ.get(env_var)}")

        #     if type()


    #                      debug    bool              False
    #                export_html    NoneType          None
    #                 export_svg    NoneType          None
    #                 export_txt    NoneType          None
    #                file_prefix    NoneType          None
    #                file_suffix    NoneType          None
    #          file_to_scan_path    str               tests/file_fixtures/random_bytes.bin
    #     force_decode_threshold    float             50.0
    #    force_display_threshold    float             20.0
    #               hex_patterns    NoneType          None
    #                   interact    bool              False
    #                  log_level    NoneType          None
    #          max_decode_length    int               256
    #           max_match_length    int               102400
    #             maximize_width    bool              False
    #          min_chardet_bytes    int               9
    #          min_decode_length    int               1
    #                 output_dir    NoneType          None
    #             patterns_label    NoneType          None
    #             regex_modifier    NoneType          None
    #             regex_patterns    NoneType          None
    #           suppress_chardet    bool              False
    #     suppress_decodes_table    bool              False
    # suppress_decoding_attempts    bool              False
    #          surrounding_bytes    int               64
    #                    version    bool              False
    #            yara_rules_dirs    NoneType          None
    #           yara_rules_files    list              ['tests/file_fixtures/tulips.yara']
    #            yara_stack_size    int               131072
