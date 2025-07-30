import logging
import re
import sys
from argparse import ArgumentError, ArgumentParser, Namespace
from collections import namedtuple
from importlib.metadata import version
from os import getcwd, path
from typing import Optional

from rich_argparse_plus import RichHelpFormatterPlus

from yaralyzer.config import YaralyzerConfig
from yaralyzer.encoding_detection.encoding_detector import CONFIDENCE_SCORE_RANGE, EncodingDetector
from yaralyzer.helpers.file_helper import timestamp_for_filename
from yaralyzer.helpers.string_helper import comma_join
from yaralyzer.output import rich_console
from yaralyzer.yara.yara_rule_builder import YARA_REGEX_MODIFIERS
from yaralyzer.util.logging import log, log_argparse_result, log_current_config, log_invocation
from yaralyzer.yaralyzer import Yaralyzer


# NamedTuple to keep our argument selection orderly
OutputSection = namedtuple('OutputSection', ['argument', 'method'])

YARA_PATTERN_LABEL_REGEX = re.compile('^\\w+$')
YARA_RULES_ARGS = ['yara_rules_files', 'yara_rules_dirs', 'hex_patterns', 'regex_patterns']
DESCRIPTION = "Get a good hard colorful look at all the byte sequences that make up a YARA rule match. "

EPILOG = "* Values for various config options can be set permanently by a .yaralyzer file in your home directory; " + \
         "see the documentation for details.\n" + \
         f"* A registry of previous yaralyzer invocations will be incribed to a file if the " + \
         f"{YaralyzerConfig.LOG_DIR_ENV_VAR} environment variable is configured."


# Positional args, version, help, etc
RichHelpFormatterPlus.choose_theme('prince')
parser = ArgumentParser(formatter_class=RichHelpFormatterPlus, description=DESCRIPTION, epilog=EPILOG)
parser.add_argument('--version', action='store_true', help='show version number and exit')
parser.add_argument('file_to_scan_path', metavar='FILE', help='file to scan')

source = parser.add_argument_group(
    'YARA RULES',
    "Load YARA rules from preconfigured files or use one off YARA regular expression strings")

source.add_argument('--yara-file', '-Y',
                    help='path to a YARA rules file to check against (can be supplied more than once)',
                    action='append',
                    metavar='FILE',
                    dest='yara_rules_files')

source.add_argument('--rule-dir', '-dir',
                    help='directory with yara rules files (all files are used, can be supplied more than once)',
                    action='append',
                    metavar='DIR',
                    dest='yara_rules_dirs')

source.add_argument('--regex-pattern', '-re',
                    help='build a YARA rule from PATTERN and run it (can be supplied more than once for boolean OR)',
                    action='append',
                    metavar='PATTERN',
                    dest='regex_patterns')

source.add_argument('--hex-pattern', '-hex',
                    help='build a YARA rule from HEX_STRING and run it (can be supplied more than once for boolean OR)',
                    action='append',
                    metavar='HEX_STRING',
                    dest='hex_patterns')

source.add_argument('--patterns-label', '-rpl',
                    help='supplying an optional STRING to label your YARA patterns makes it easier to scan results',
                    metavar='STRING')

source.add_argument('--regex-modifier', '-mod',
                    help=f"optional modifier keyword for YARA regexes ({comma_join(YARA_REGEX_MODIFIERS)})",
                    metavar='MODIFIER',
                    choices=YARA_REGEX_MODIFIERS)

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
                    default=YaralyzerConfig.DEFAULT_SURROUNDING_BYTES,
                    metavar='N',
                    type=int)

tuning.add_argument('--suppress-decodes-table', action='store_true',
                    help='suppress decodes table entirely (including hex/raw output)')

tuning.add_argument('--suppress-decoding-attempts', action='store_true',
                    help='suppress decode attempts for matched bytes (only hex/raw output will be shown)')

tuning.add_argument('--min-decode-length',
                    help='suppress decode attempts for quoted byte sequences shorter than N',
                    default=YaralyzerConfig.DEFAULT_MIN_DECODE_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--max-decode-length',
                    help='suppress decode attempts for quoted byte sequences longer than N',
                    default=YaralyzerConfig.DEFAULT_MAX_DECODE_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--suppress-chardet', action='store_true',
                    help="suppress the display of the full table of chardet's encoding likelihood scores")

tuning.add_argument('--min-chardet-bytes',
                    help="minimum number of bytes to run chardet.detect() and the decodings it suggests",
                    default=YaralyzerConfig.DEFAULT_MIN_CHARDET_BYTES,
                    metavar='N',
                    type=int)

tuning.add_argument('--min-chardet-table-confidence',
                    help="minimum chardet confidence to display the encoding name/score in the character " + \
                         "decection scores table",
                    default=YaralyzerConfig.DEFAULT_MIN_CHARDET_TABLE_CONFIDENCE,
                    metavar='PCT_CONFIDENCE',
                    type=int)

tuning.add_argument('--force-display-threshold',
                    help="encodings with chardet confidence below this number will neither be displayed nor " + \
                         "decoded in the decodings table",
                    default=EncodingDetector.force_display_threshold,
                    metavar='PCT_CONFIDENCE',
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)

tuning.add_argument('--force-decode-threshold',
                    help="extremely high (AKA 'above this number') confidence scores from chardet.detect() " + \
                         "as to the likelihood some bytes were written with a particular encoding will cause " + \
                         "the yaralyzer to attempt decoding those bytes in that encoding even if it is not a " + \
                         "configured encoding",
                    default=EncodingDetector.force_decode_threshold,
                    metavar='PCT_CONFIDENCE',
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)

tuning.add_argument('--max-match-length',
                    help="max bytes YARA will return for a match",
                    default=YaralyzerConfig.DEFAULT_MAX_MATCH_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--yara-stack-size',
                    help="YARA matching engine internal stack size",
                    default=YaralyzerConfig.DEFAULT_YARA_STACK_SIZE,
                    metavar='N',
                    type=int)


# Export options
export = parser.add_argument_group(
    'FILE EXPORT',
    "Multiselect. Choosing nothing is choosing nothing. Sends what you see on the screen to various file " + \
        "formats in parallel. Writes files to the current directory if --output-dir is not provided. " + \
        "Filenames are expansions of the scanned filename though you can use --file-prefix to make your " +
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

export.add_argument('-json', '--export-json',
                    action='store_const',
                    const='json',
                    help='export analysis to JSON files')

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

debug.add_argument('-L', '--log-level',
                    help='set the log level',
                    choices=['DEBUG', 'INFO', 'WARN', 'ERROR'])

YaralyzerConfig.set_argument_parser(parser)


def parse_arguments(args: Optional[Namespace] = None):
    """
    Parse command line args. Most settings can be communicated to the app by setting env vars.
    If args are passed neither rules nor a regex need be provided as it is assumed
    the constructor will instantiate a Yaralyzer object directly.
    """
    if '--version' in sys.argv:
        print(f"yaralyzer {version('yaralyzer')}")
        sys.exit()

    # Hacky way to adjust arg parsing based on whether yaralyzer is used as a library vs. CLI tool
    used_as_library = args is not None
    args = args or parser.parse_args()
    log_argparse_result(args, 'RAW')
    args.standalone_mode = not used_as_library
    args.invoked_at_str = timestamp_for_filename()

    if args.debug:
        log.setLevel(logging.DEBUG)

        if args.log_level and args.log_level != 'DEBUG':
            log.warning("Ignoring --log-level option as debug mode means log level is DEBUG")
    elif args.log_level:
        log.setLevel(args.log_level)

    yara_rules_args = [arg for arg in YARA_RULES_ARGS if vars(args)[arg] is not None]

    if used_as_library:
        pass
    elif len(yara_rules_args) > 1:
        raise ArgumentError(None, "Cannot mix rules files, rules dirs, and regex patterns (for now).")
    elif len(yara_rules_args) == 0:
        raise ArgumentError(None, "You must provide either a YARA rules file or a regex pattern")
    else:
        log_invocation()

    if args.maximize_width:
        rich_console.console.width = max(rich_console.console_width_possibilities())

    if args.patterns_label and not YARA_PATTERN_LABEL_REGEX.match(args.patterns_label):
        raise ArgumentError(None, 'Pattern can only include alphanumeric chars and underscore')

    # chardet.detect() action thresholds
    if args.force_decode_threshold:
        EncodingDetector.force_decode_threshold = args.force_decode_threshold

    if args.force_display_threshold:
        EncodingDetector.force_display_threshold = args.force_display_threshold

    # File export options
    if args.export_html or args.export_json or args.export_svg or args.export_txt:
        args.output_dir = args.output_dir or getcwd()
    elif args.output_dir:
        log.warning('--output-dir provided but no export option was chosen')

    YaralyzerConfig.set_args(args)

    if not used_as_library:
        log_argparse_result(args, 'parsed')
        log_current_config()
        log_argparse_result(YaralyzerConfig.args, 'with_env_vars')

    return args


def get_export_basepath(args: Namespace, yaralyzer: Yaralyzer):
    file_prefix = (args.file_prefix + '_') if args.file_prefix else ''
    args.output_basename =  f"{file_prefix}{yaralyzer._filename_string()}"
    args.output_basename += f"__maxdecode{YaralyzerConfig.args.max_decode_length}"
    args.output_basename += ('_' + args.file_suffix) if args.file_suffix else ''
    return path.join(args.output_dir, args.output_basename + f"__at_{args.invoked_at_str}")
