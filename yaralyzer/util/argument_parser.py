"""Argument parsing for yaralyzer CLI tool."""
import logging
import re
import sys
from argparse import ArgumentParser, Namespace
from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from rich_argparse_plus import RichHelpFormatterPlus
from yaralyzer.config import YaralyzerConfig
from yaralyzer.encoding_detection.encoding_detector import CONFIDENCE_SCORE_RANGE, EncodingDetector
from yaralyzer.helpers import env_helper
from yaralyzer.helpers.file_helper import timestamp_for_filename
from yaralyzer.helpers.string_helper import comma_join
from yaralyzer.output import rich_console
from yaralyzer.util.constants import YARALYZE, YARALYZER
from yaralyzer.util.exceptions import handle_argument_error
from yaralyzer.util.logging import TRACE, log, log_argparse_result, log_current_config, log_invocation, set_log_level
from yaralyzer.yara.yara_rule_builder import YARA_REGEX_MODIFIERS

DESCRIPTION = "Get a good hard colorful look at all the byte sequences that make up a YARA rule match."
GITHUB_BASE_URL = 'https://github.com/michelcrypt4d4mus'
YARALYZER_API_DOCS_URL = 'https://michelcrypt4d4mus.github.io/yaralyzer'
YARA_PATTERN_LABEL_REGEX = re.compile('^\\w+$')
YARA_RULES_ARGS = ['yara_rules_files', 'yara_rules_dirs', 'hex_patterns', 'regex_patterns']


def epilog(package: str) -> str:
    color_var = lambda s: f"[argparse.metavar]{s}[/argparse.metavar]"
    color_link = lambda s: f"[argparse.metavar]{s}[/argparse.metavar]"
    readme_url = f"{GITHUB_BASE_URL}/{package}"

    msg = f"Values for some options can be set permanently by creating a {color_var(f'.{package}')} " \
          f"file. See the documentation for details.\n" \
          f"A log of previous {package} invocation args will be inscribed to a file if the " \
          f"{color_var(YaralyzerConfig.LOG_DIR_ENV_VAR)} environment variable is configured." \

    if package == YARALYZER:
        msg += f"\n[gray46]API docs: {color_link(YARALYZER_API_DOCS_URL)}[/gray46]"

    return msg # + f"README: {color_link(readme_url)}"


# Positional args, version, help, etc
RichHelpFormatterPlus.choose_theme('prince')  # Check options: print(RichHelpFormatterPlus.styles)
parser = ArgumentParser(formatter_class=RichHelpFormatterPlus, description=DESCRIPTION, epilog=epilog(YARALYZER))
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
                    help='directory with yara rules files (all files in dir are used, can be supplied more than once)',
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
                    help='supply an optional STRING to label your YARA patterns makes it easier to scan results',
                    metavar='STRING')

source.add_argument('--regex-modifier', '-mod',
                    help=f"optional modifier keyword for YARA regexes ({comma_join(YARA_REGEX_MODIFIERS)})",
                    metavar='MODIFIER',
                    choices=YARA_REGEX_MODIFIERS)

# Fine tuning
tuning = parser.add_argument_group(
    'FINE TUNING',
    "Tune various aspects of the analyses and visualizations to your needs. As an example setting " +
        "a low --max-decode-length (or suppressing brute force binary decode attempts altogether) can " +
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
                    help="minimum chardet confidence to display the encoding name/score in the character " +
                         "decection scores table",
                    default=YaralyzerConfig.DEFAULT_MIN_CHARDET_TABLE_CONFIDENCE,
                    metavar='PCT_CONFIDENCE',
                    type=int)

tuning.add_argument('--force-display-threshold',
                    help="encodings with chardet confidence below this number will neither be displayed nor " +
                         "decoded in the decodings table",
                    default=EncodingDetector.force_display_threshold,
                    metavar='PCT_CONFIDENCE',
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)

tuning.add_argument('--force-decode-threshold',
                    help="extremely high (AKA 'above this number') confidence scores from chardet.detect() " +
                         "as to the likelihood some bytes were written with a particular encoding will cause " +
                         "the yaralyzer to attempt decoding those bytes in that encoding even if it is not a " +
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
    "Multiselect. Choosing nothing is choosing nothing. Sends what you see on the screen to various file " +
        "formats in parallel. Writes files to the current directory if --output-dir is not provided. " +
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
                    help='optional string to use as the prefix for exported files of any kind',
                    default='')

export.add_argument('-sfx', '--file-suffix',
                    metavar='SUFFIX',
                    help='optional string to use as the suffix for exported files of any kind',
                    default='')

export.add_argument('--no-timestamps', action='store_true',
                    help="do not append file creation timestamps to exported filenames")


# Debugging
debug = parser.add_argument_group(
    'DEBUG',
    'Debugging/interactive options.')

debug.add_argument('-D', '--debug', action='store_true',
                    help='show verbose debug log output')

debug.add_argument('-L', '--log-level',
                    help='set the log level',
                    choices=[TRACE, 'DEBUG', 'INFO', 'WARN', 'ERROR'])

debug.add_argument('-I', '--interact', action='store_true',
                    help='drop into interactive python REPL when parsing is complete')

debug.add_argument('--echo-command', action='store_true',
                   help="print the exact command line used first (useful if you're revisiting old exports)")

YaralyzerConfig.set_argument_parser(parser)
is_yaralyzing = parser.prog == YARALYZE


def parse_arguments(args: Namespace | None = None, argv: list[str] | None = None):
    """
    Parse command line args. Most arguments can also be communicated to the app by setting env vars.
    If `args` are passed neither rules nor a regex need be provided as it is assumed
    the constructor will instantiate a `Yaralyzer` object directly.

    Args:
        args (Namespace, optional): If provided, use these args instead of parsing from command line.
        argv (list[str], optional): Use these args instead of sys.argv.

    Raises:
        InvalidArgumentError: If args are invalid.
    """
    if '--version' in sys.argv:
        print(f"yaralyzer {version('yaralyzer')}")
        sys.exit()

    # Hacky way to adjust arg parsing based on whether yaralyzer is used as a library vs. CLI tool
    is_used_as_library = args is not None
    handle_invalid_args = partial(handle_argument_error, is_used_as_library=is_used_as_library)

    # Parse and validate args
    args = args or parser.parse_args(argv)
    log_argparse_result(args, 'RAW')
    args.invoked_at_str = timestamp_for_filename()
    args.standalone_mode = not is_used_as_library

    if args.debug:
        set_log_level(logging.DEBUG)

        if args.log_level and args.log_level != 'DEBUG':
            log.warning("Ignoring --log-level option as debug mode means log level is DEBUG")
    elif args.log_level:
        set_log_level(args.log_level)

    if args.output_dir and not any(arg.startswith('export') and val for arg, val in vars(args).items()):
        log.warning('--output-dir provided but no export option was chosen')

    args.file_to_scan_path = Path(args.file_to_scan_path)
    yara_rules_args = [arg for arg in YARA_RULES_ARGS if vars(args)[arg] is not None]

    if not args.file_to_scan_path.exists():
        handle_invalid_args(f"'{args.file_to_scan_path}' is not a valid file.")

    if is_used_as_library:
        pass
    elif len(yara_rules_args) > 1:
        handle_invalid_args("Cannot mix rules files, rules dirs, and regex patterns (for now).")
    elif len(yara_rules_args) == 0:
        handle_invalid_args("You must provide either a YARA rules file or a regex pattern")
    else:
        log_invocation()

    if args.patterns_label and not YARA_PATTERN_LABEL_REGEX.match(args.patterns_label):
        handle_invalid_args('Pattern can only include alphanumeric chars and underscore')

    # chardet.detect() action thresholds
    if args.force_decode_threshold:
        EncodingDetector.force_decode_threshold = args.force_decode_threshold

    if args.force_display_threshold:
        EncodingDetector.force_display_threshold = args.force_display_threshold

    YaralyzerConfig.set_args(args)

    # Wait until after set_args() to set these defaults in case there's a YARALYZER_[WHATEVER] env var
    # that we need to override.
    args.file_prefix = (args.file_prefix + '__') if args.file_prefix else ''
    args.file_suffix = ('_' + args.file_suffix) if args.file_suffix else ''
    args.output_dir = Path(args.output_dir or Path.cwd()).resolve()

    if not args.output_dir.is_dir():
        handle_invalid_args(f"'{args.output_dir}' is not a valid directory.")

    if args.maximize_width:
        rich_console.console.width = max(env_helper.console_width_possibilities())

    if not is_used_as_library:
        log_argparse_result(args, 'parsed')
        log_current_config()
        log_argparse_result(YaralyzerConfig.args, 'with_env_vars')

    return args


YaralyzerConfig.parse_arguments = parse_arguments
