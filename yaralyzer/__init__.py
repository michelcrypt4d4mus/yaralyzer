import code
import yara as python_yara
from os import environ, getcwd, path
from pathlib import Path

from dotenv import load_dotenv
from rich.text import Text

# load_dotenv() should be called as soon as possible (before parsing local classes) but not for pytest
from yaralyzer.util.constants import INVOKED_BY_PYTEST

if not environ.get(INVOKED_BY_PYTEST, False):
    for dotenv_file in [path.join(dir, '.yaralyzer') for dir in [getcwd(), path.expanduser('~')]]:
        if path.exists(dotenv_file):
            load_dotenv(dotenv_path=dotenv_file)
            break

from yaralyzer.output.console import console
from yaralyzer.output.file_export import export_json, invoke_rich_export
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.constants import PDFALYZER_REPO_URL
from yaralyzer.util.helpers.rich_helper import print_fatal_error_and_exit
from yaralyzer.util.helpers.file_helper import relative_path
from yaralyzer.util.logging import invocation_txt, log, log_console
from yaralyzer.yara.error import yara_error_msg
from yaralyzer.yara.yara_rule_builder import HEX, REGEX
from yaralyzer.yaralyzer import Yaralyzer

PDFALYZER_MSG = "\nIf you are analyzing a PDF you may be interested in Pdfalyzer, birthplace of the Yaralyzer:"
PDFALYZER_MSG_TXT = Text(PDFALYZER_MSG, style='bright_white bold').append('\n -> ', style='bright_white')
PDFALYZER_MSG_TXT.append(f'{PDFALYZER_REPO_URL}\n', style='bright_cyan underline')


def yaralyze():
    """
    Entry point for Yaralyzer when invoked as a script. Args are parsed from the command line
    and environment variables. See `yaralyze --help` for details.
    """
    args = parse_arguments()

    if args.yara_rules_files:
        yaralyzer = Yaralyzer.for_rules_files(args.yara_rules_files, args.file_to_scan_path)
    elif args.yara_rules_dirs:
        yaralyzer = Yaralyzer.for_rules_dirs(args.yara_rules_dirs, args.file_to_scan_path)
    elif args.regex_patterns or args.hex_patterns:
        yaralyzer = Yaralyzer.for_patterns(
            args.regex_patterns or args.hex_patterns,
            HEX if args.hex_patterns else REGEX,
            args.file_to_scan_path,
            pattern_label=args.patterns_label,
            regex_modifier=args.regex_modifier
        )
    else:
        raise RuntimeError("No pattern or YARA file to scan against.")

    args._export_basepath = yaralyzer.export_basepath()

    if args._any_export_selected:
        log.debug(f"export_basepath is '{relative_path(args._export_basepath)}'...")
        console.record = True

    if args.echo_command:
        console.print(invocation_txt())

    try:
        yaralyzer.yaralyze()
    except python_yara.Error as e:
        print_fatal_error_and_exit(yara_error_msg(e))

    if args.export_txt:
        invoke_rich_export(console.save_text, args)
    if args.export_html:
        invoke_rich_export(console.save_html, args)
    if args.export_svg:
        invoke_rich_export(console.save_svg, args)
    if args.export_json:
        export_json(yaralyzer, args._export_basepath)

    if str(args.file_to_scan_path).lower().endswith('pdf'):
        log_console.print(PDFALYZER_MSG_TXT)

    # Drop into interactive shell if requested
    if args.interact:
        code.interact(local=locals())
