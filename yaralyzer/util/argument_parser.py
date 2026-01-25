"""Argument parsing for yaralyzer CLI tool."""
import logging
import re
import sys
from argparse import ArgumentParser, Namespace
from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Type

from rich_argparse_plus import RichHelpFormatterPlus
from yaralyzer.config import YaralyzerConfig
from yaralyzer.encoding_detection.encoding_detector import CONFIDENCE_SCORE_RANGE, EncodingDetector
from yaralyzer.output import console
from yaralyzer.util.constants import *
from yaralyzer.util.exceptions import handle_argument_error
from yaralyzer.util.helpers import env_helper
from yaralyzer.util.helpers.cli_option_validators import DirArgValidator, FileArgValidator, PatternsLabelValidator, YaraRegexValidator
from yaralyzer.util.helpers.file_helper import timestamp_for_filename
from yaralyzer.util.helpers.shell_helper import get_inkscape_version
from yaralyzer.util.helpers.string_helper import comma_join
from yaralyzer.util.logging import log, log_argparse_result, log_current_config, log_invocation, set_log_level
from yaralyzer.yara.yara_rule_builder import YARA_REGEX_MODIFIERS

DESCRIPTION = "Get a good hard colorful look at all the byte sequences that make up a YARA rule match."
YARA_RULES_ARGS = ['yara_rules_files', 'yara_rules_dirs', 'hex_patterns', 'regex_patterns']

PNG_EXPORT_ERROR_MSG = f"PNG export requires CairoSVG or Inkscape and you have neither.\n" \
                       f"Maybe try pip install {YARALYZER}[img] or {INKSCAPE_URL}"


def epilog(config: Type[YaralyzerConfig]) -> str:
    """Returns a string with some rich text tags for color."""
    color_var = lambda s: f"[argparse.metavar]{s}[/argparse.metavar]"
    color_link = lambda s: f"[argparse.metavar]{s}[/argparse.metavar]"
    package = config.ENV_VAR_PREFIX.lower()

    msg = f"Values for most command options can be permanently set by setting via env vars or creating a " \
          f" {color_var(f'.{package}')} file. Try [argparse.args]{config.executable} {ENV_VARS_OPTION}" \
          f"[/argparse.args] for more info." \

    if package == YARALYZER:
        msg += f"\n[gray46]API docs: {color_link(YARALYZER_API_DOCS_URL)}[/gray46]"

    return msg


# Positional args, version, help, etc
RichHelpFormatterPlus.choose_theme('prince')  # Check options: print(RichHelpFormatterPlus.styles)
parser = ArgumentParser(formatter_class=RichHelpFormatterPlus, description=DESCRIPTION, epilog=epilog(YaralyzerConfig))
parser.add_argument('file_to_scan_path', metavar='FILE', help='file to scan', type=FileArgValidator())
parser.add_argument('--version', action='store_true', help='show version number and exit')
parser.add_argument('--maximize-width', action='store_true', help="maximize display width to fill the terminal")

parser.add_argument(ENV_VARS_OPTION, action='store_true',
                    help=f"show the env vars that can set these options permanently if placed in a .{parser.prog}r file")


rules = parser.add_argument_group(
    'YARA RULES',
    "Load YARA rules from preconfigured files or use one off YARA regular expression strings")

rules.add_argument('-Y', '--yara-file',
                    help='path to a YARA rules file to check against (can be supplied more than once)',
                    action='append',
                    metavar='FILE',
                    dest='yara_rules_files',
                    type=FileArgValidator())

rules.add_argument('-dir', '--rule-dir',
                    help='directory with yara rules files (all files in dir are used, can be supplied more than once)',
                    action='append',
                    metavar='DIR',
                    dest='yara_rules_dirs',
                    type=DirArgValidator())

rules.add_argument('-re', '--regex-pattern',
                    help='build a YARA rule from PATTERN and run it (can be supplied more than once for boolean OR)',
                    action='append',
                    metavar='PATTERN',
                    dest='regex_patterns',
                    type=YaraRegexValidator())

rules.add_argument('-hex', '--hex-pattern',
                    help='build a YARA rule from HEX_STRING and run it (can be supplied more than once for boolean OR)',
                    action='append',
                    metavar='HEX_STRING',
                    dest='hex_patterns',
                    type=YaraRegexValidator())

rules.add_argument('-rpl', '--patterns-label',
                    help='supply an optional STRING to label your YARA patterns makes it easier to scan results',
                    metavar='STRING',
                    type=PatternsLabelValidator())

rules.add_argument('-mod', '--regex-modifier',
                    help=f"optional modifier keyword for YARA regexes ({comma_join(YARA_REGEX_MODIFIERS)})",
                    metavar='MODIFIER',
                    choices=YARA_REGEX_MODIFIERS)


# Fine tuning
tuning = parser.add_argument_group(
    'FINE TUNING',
    "Tune various aspects of the analyses and visualizations to your needs. As an example setting " +
        "a low --max-decode-length (or suppressing brute force binary decode attempts altogether) can " +
        "dramatically improve run times and only occasionally leads to a fatal lack of insight.")

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
                    type=int,
                    choices=CONFIDENCE_SCORE_RANGE)

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
                    help="max bytes YARA will return for a match (value is passed to YARA)",
                    default=YaralyzerConfig.DEFAULT_MAX_MATCH_LENGTH,
                    metavar='N',
                    type=int)

tuning.add_argument('--yara-stack-size',
                    help="YARA matching engine internal stack size (value is passed to YARA)",
                    default=YaralyzerConfig.DEFAULT_YARA_STACK_SIZE,
                    metavar='N',
                    type=int)


# Export options
export = parser.add_argument_group(
    'FILE EXPORT',
    "Multiselect. Choosing nothing is choosing nothing. Sends what you see on the screen to various file " +
        "formats in parallel. Writes files to the current directory if --output-dir is not provided. " +
        "Filenames are expansions of the scanned filename though you can use --file-prefix and " +
        "--file-suffix to make your rendered files more unique and beautiful to their beholder.")

export.add_argument('-html', '--export-html', action='store_const',
                    const='html',
                    help='export analysis to styled html files')

export.add_argument('-txt', '--export-txt', action='store_const',
                    const='txt',
                    help='export analysis to ANSI colored text files')

export.add_argument('-svg', '--export-svg', action='store_const',
                    const='svg',
                    help='export analysis to SVG images')

export.add_argument('-png', '--export-png', action='store_true',
                    help='export analysis to PNG images (requires cairosvg or inkscape)')

export.add_argument('-json', '--export-json', action='store_const',
                    const='json',
                    help='export analysis to JSON files (experimental / possibly incomplete)')

export.add_argument('-out', '--output-dir',
                    metavar='OUTPUT_DIR',
                    help='write files to OUTPUT_DIR instead of current dir, does nothing if not exporting a file',
                    type=DirArgValidator())

export.add_argument('-pfx', '--file-prefix',
                    metavar='PREFIX',
                    help='optional string to use as the prefix for exported files of any kind',
                    default='')

export.add_argument('-sfx', '--file-suffix',
                    metavar='SUFFIX',
                    help='optional string to use as the suffix for exported files of any kind',
                    default='')

export.add_argument(ECHO_COMMAND_OPTION, action='store_true',
                   help="prepend the exact command line used to the output (useful for revisiting old exports)")

export.add_argument(NO_TIMESTAMPS_OPTION, action='store_true',
                    help="do not append file creation timestamps to exported filenames")

export.add_argument(SUPPRESS_OUTPUT_OPTION, action='store_true',
                    help="no output to terminal (useful when you're exporting HTML etc.)")


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

# TODO: this kind of sucks
YaralyzerConfig.set_argument_parser(parser)


def parse_arguments(_args: Namespace | None = None, argv: list[str] | None = None):
    """
    Parse command line args. Most arguments can also be communicated to the app by setting env vars.
    If `args` is provided it should have come from `parser.parse_args()` by an `ArgumentParser`
    that inherits from Yaralyzer's. Also if 'args' is provided neither rules nor a regex
    nor a regex need be provided as it is assumed the constructor will instantiate a
    `Yaralyzer` object directly.

    "Private" options injected by this method outside of user selection will be prefixed with underscore.

    Args:
        args (Namespace, optional): If provided, use these args instead of parsing from command line.
        argv (list[str], optional): Use these args instead of sys.argv.

    Raises:
        InvalidArgumentError: If args are invalid.
    """
    if '--version' in sys.argv:
        print(f"{YARALYZER} {version(YARALYZER)}")
        sys.exit()
    elif ENV_VARS_OPTION in sys.argv:
        YaralyzerConfig.show_configurable_env_vars()
        sys.exit()

    # Parse and validate args
    args = _args or parser.parse_args(argv)
    args._invoked_at_str = timestamp_for_filename()
    args._standalone_mode = _args is None
    # Adjust error handling based on whether the 'yaralyze' shell script is what's being run
    handle_invalid_args = partial(handle_argument_error, is_standalone_mode=args._standalone_mode)

    if args.debug:
        set_log_level(logging.DEBUG)

        if args.log_level and args.log_level != 'DEBUG':
            log.warning("Ignoring --log-level option, --debug means log level is DEBUG")
    elif args.log_level:
        set_log_level(args.log_level)

    log_argparse_result(args, 'RAW')
    num_selected_yara_rules_options = len([arg for arg in YARA_RULES_ARGS if vars(args)[arg] is not None])
    args._any_export_selected = any(arg for arg, val in vars(args).items() if arg.startswith('export') and val)
    args._svg_requested = bool(args.export_svg)  # So we can clean up intermediate SVG when -png but not -svg

    # If yaralyzer is in use as a library for pdfalyzer Yara rules args are not required
    if not args._standalone_mode:
        pass
    elif num_selected_yara_rules_options == 0:
        handle_invalid_args("You must provide either a YARA rules file, a dir with such files, or a regex")
    elif num_selected_yara_rules_options > 1:
        handle_invalid_args("Cannot mix rules files, rules dirs, and regex patterns (for now).")
    else:
        log_invocation()

    if args.output_dir and not args._any_export_selected:
        log.warning('--output-dir provided but no export option was chosen')

    if args.export_png:
        if not (env_helper.is_cairosvg_installed() or get_inkscape_version()):
            handle_invalid_args(PNG_EXPORT_ERROR_MSG)
        elif not args.export_svg:
            args.export_svg = 'svg'  # SVGs are necessary intermediate step for PNGs

    # chardet.detect() action thresholds
    if args.force_decode_threshold:
        EncodingDetector.force_decode_threshold = args.force_decode_threshold
    if args.force_display_threshold:
        EncodingDetector.force_display_threshold = args.force_display_threshold

    YaralyzerConfig.set_args(args)

    # Wait until after set_args() to set these defaults in case there's a YARALYZER_[WHATEVER] env var
    # that we need to override.
    args.output_dir = (args.output_dir or Path.cwd()).resolve()
    args.file_prefix = (args.file_prefix + '__') if args.file_prefix else ''
    args.file_suffix = ('_' + args.file_suffix) if args.file_suffix else ''

    if args.maximize_width:
        # TODO: unclear if we need to do this import this way to make the change happen?
        console.console.width = max(env_helper.console_width_possibilities())

    if args._standalone_mode:
        log_argparse_result(args, 'parsed')
        log_current_config()
        log_argparse_result(YaralyzerConfig.args, 'with_env_vars')

    return args


# TODO this is hacky/ugly
YaralyzerConfig._parse_arguments = parse_arguments
