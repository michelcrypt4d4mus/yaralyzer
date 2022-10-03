import logging
import sys
from argparse import ArgumentError, ArgumentDefaultsHelpFormatter, ArgumentParser
from collections import namedtuple
from importlib.metadata import version
from os import environ, getcwd, path

from rich_argparse import RichHelpFormatter

from yaralyzer.config import (DEFAULT_MIN_DECODE_LENGTH, DEFAULT_MAX_DECODE_LENGTH,
     DEFAULT_MIN_BYTES_TO_DETECT_ENCODING, LOG_DIR_ENV_VAR, SURROUNDING_BYTES_LENGTH_DEFAULT,
     YaralyzerConfig)
from yaralyzer.encoding_detection.encoding_detector import CONFIDENCE_SCORE_RANGE, EncodingDetector
from yaralyzer.helpers import rich_text_helper
from yaralyzer.helpers.file_helper import timestamp_for_filename
from yaralyzer.helpers.rich_text_helper import console, console_width_possibilities
from yaralyzer.util.logging import invocation_log, log, log_and_print, log_current_config


# NamedTuple to keep our argument selection orderly
OutputSection = namedtuple('OutputSection', ['argument', 'method'])

# Class to enable defaults to only be printed when they are not None or False
class ExplicitDefaultsHelpFormatter(RichHelpFormatter):
#class ExplicitDefaultsHelpFormatter(ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action):
        if 'default' in vars(action) and action.default in (None, False):
            return action.help
        else:
            return super()._get_help_string(action)


ARGPARSE_LOG_FORMAT = '{0: >30}    {1: <17} {2: <}\n'
DESCRIPTION = "Get a good hard look at all the byte sequences that make up a YARA rule match. "

EPILOG = "* Values for various config options can be set permanently by a .yaralyzer file in your home directory; " + \
         "see the documentation for details.\n" + \
         f"* A registry of previous yaralyzer invocations will be incribed to a file if the '{LOG_DIR_ENV_VAR}' " + \
         "environment variable is configured."


# Positional args, version, help, etc
parser = ArgumentParser(formatter_class=ExplicitDefaultsHelpFormatter, description=DESCRIPTION, epilog=EPILOG)
parser.add_argument('--version', action='version', version=f"yaralyzer {version('yaralyzer')}")
parser.add_argument('file_to_scan_path', metavar='FILE', help='file to scan')


yara_r = parser.add_argument_group(
    'YARA RULES',
    "Load YARA rules from preconfigured files or use one off YARA regular expression strings")

yara_r.add_argument('--yara-rules', '-y',
                    help='path to a YARA rules file to check against (can be supplied more than once)',
                    action='append',
                    dest='yara_rules_files',
                    metavar='FILE')

#parser.add_argument('--rules-dir', '-d', help='directory with YARA rules files (all will be checke)')

yara_r.add_argument('--regex-pattern', '-r',
                    help='build a rule from PATTERN and run it (can be supplied more than once)',
                    metavar='PATTERN',
                    dest='yara_patterns',
                    action='append')

# Fine tuning
tuning = parser.add_argument_group(
    'FINE TUNING',
    "Tune various aspects of the analyses and visualizations to your needs. As an example setting " + \
        "a low --max-decode-length (or suppressing brute force binary decode attempts altogether) can " + \
        "dramatically improve run times and only occasionally leads to a fatal lack of insight.")

tuning.add_argument('--maximize-width', action='store_true',
                    help="maximize the display width to fill the terminal")

tuning.add_argument('--surrounding-bytes',
                    help="number of bytes to display/decode before and after YARA match start positions",
                    default=SURROUNDING_BYTES_LENGTH_DEFAULT,
                    metavar='N',
                    type=int)

tuning.add_argument('--suppress-chardet', action='store_true',
                    help="suppress the display of the full table of chardet's encoding likelihood scores")

tuning.add_argument('--min-chardet-bytes',
                    help="minimum number of bytes to run chardet.detect() and the decodings it suggests",
                    default=DEFAULT_MIN_BYTES_TO_DETECT_ENCODING,
                    metavar='N',
                    type=int)

tuning.add_argument('--suppress-decodes', action='store_true',
                    help='suppress decode attempts for quoted bytes found in font binaries')

tuning.add_argument('--min-decode-length',
                    help='suppress decode attempts for quoted byte sequences shorter than N',
                    default=DEFAULT_MIN_DECODE_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--max-decode-length',
                    help='suppress decode attempts for quoted byte sequences longer than N',
                    default=DEFAULT_MAX_DECODE_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--force-display-threshold',
                    help="encodings with chardet confidence below this number will not be displayed (range: 0-100)",
                    default=EncodingDetector.force_display_threshold,
                    metavar='PCT_CONFIDENCE',
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)

tuning.add_argument('--force-decode-threshold',
                    help="extremely high (AKA 'above this number') PCT_CONFIDENCE scores from chardet.detect() " + \
                         "as to the likelihood some binary data was written with a particular encoding will cause " + \
                         "the yaralyzer to do a force decode of that with that encoding. " + \
                         "(chardet is a sophisticated libary; this is yaralyzer's way of harnessing that intelligence)",
                    default=EncodingDetector.force_decode_threshold,
                    metavar='PCT_CONFIDENCE',
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)


# Export options
export = parser.add_argument_group(
    'FILE EXPORT',
    "Multiselect. Choosing nothing is choosing nothing. Sends what you see on the screen to various file " + \
        "formats in parallel. Writes files to the current directory if --output-dir is not provided. " + \
        "Filenames are expansion of the scanned filename though you can use --file-prefix to make your " +
        "filenames more unique and beautiful to their beholder.")

export.add_argument('-svg', '--export-svg',
                    action='store_const',
                    const='svg',
                    help='export analysis to SVG images')

export.add_argument('-txt', '--export-txt',
                    action='store_const',
                    const='txt',
                    help='export analysis to ANSI colored text files')

export.add_argument('-html', '--export-html',
                    action='store_const',
                    const='html',
                    help='export analysis to styled html files')

export.add_argument('-out', '--output-dir',
                    metavar='OUTPUT_DIR',
                    help='write files to OUTPUT_DIR instead of current dir, does nothing if not exporting a file')

export.add_argument('-pfx', '--file-prefix',
                    metavar='PREFIX',
                    help='optional string to use as the prefix for exported files of any kind')

export.add_argument('-sfx', '--file-suffix',
                    metavar='SUFFIX',
                    help='optional string to use as the suffix for exported files of any kind')


# Debugging
debug = parser.add_argument_group(
    'DEBUG',
    'Debugging/interactive options.')

debug.add_argument('-I', '--interact', action='store_true',
                    help='drop into interactive python REPL when parsing is complete')

debug.add_argument('-D', '--debug', action='store_true',
                    help='show verbose debug log output')


# The Parsening Begins
def parse_arguments():
    """Parse command line args. Most settings are communicated to the app by setting env vars"""
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    _log_invocation()
    args.invoked_at_str = timestamp_for_filename()

    if args.yara_rules_files and args.yara_patterns:
        raise ArgumentError(None, "Cannot specify both a regex and a YARA file (yet).")
    elif not args.yara_rules_files and not args.yara_patterns:
        raise ArgumentError(None, "You must provide either a YARA rules file or a regex pattern")

    if args.maximize_width:
        rich_text_helper.console.width = max(console_width_possibilities())

    # Suppressing/limiting output
    YaralyzerConfig.MIN_DECODE_LENGTH = args.min_decode_length
    YaralyzerConfig.MAX_DECODE_LENGTH = args.max_decode_length
    YaralyzerConfig.NUM_SURROUNDING_BYTES = args.surrounding_bytes

    if args.suppress_decodes:
        YaralyzerConfig.SUPPRESS_DECODES = args.suppress_decodes

    # chardet.detect() action thresholds
    if args.force_decode_threshold:
        EncodingDetector.force_decode_threshold = args.force_decode_threshold

    if args.force_display_threshold:
        EncodingDetector.force_display_threshold = args.force_display_threshold

    if args.suppress_chardet:
        YaralyzerConfig.SUPPRESS_CHARDET_OUTPUT = True

    # File export options
    if args.export_svg or args.export_txt or args.export_html:
        args.output_dir = args.output_dir or getcwd()
    elif args.output_dir:
        log.warning('--output-dir provided but no export option was chosen')

    _log_argparse_result(args)
    log_current_config()
    return args


def _log_invocation() -> None:
    """Log the command used to launch the yaralyzer to the invocation log"""
    msg = f"THE INVOCATION: '{' '.join(sys.argv)}'"
    log.info(msg)
    invocation_log.info(msg)


def _log_argparse_result(args):
    """Logs the result of argparse"""
    args_dict = vars(args)
    log_msg = 'argparse results:\n' + ARGPARSE_LOG_FORMAT.format('OPTION', 'TYPE', 'VALUE')

    for arg_var in sorted(args_dict.keys()):
        arg_val = args_dict[arg_var]
        row = ARGPARSE_LOG_FORMAT.format(arg_var, type(arg_val).__name__, str(arg_val))
        log_msg += row

    log_msg += "\n"
    invocation_log.info(log_msg)
    log.info(log_msg)
