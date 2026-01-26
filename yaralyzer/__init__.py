import code
import yara as python_yara
from pathlib import Path

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.console import console
from yaralyzer.output.file_export import export_json, invoke_rich_export
from yaralyzer.util.argument_parser import parser, parse_arguments
from yaralyzer.util.constants import PDFALYZER_MSG_TXT, YARALYZER
from yaralyzer.util.exceptions import print_fatal_error_and_exit
from yaralyzer.util.helpers.env_helper import load_dotenv_file
from yaralyzer.util.logging import invocation_txt, log, log_console, log_current_config
from yaralyzer.yara.error import yara_error_msg
from yaralyzer.yara.yara_rule_builder import HEX, REGEX
from yaralyzer.yaralyzer import Yaralyzer

YaralyzerConfig.init(parser, parse_arguments)


def yaralyze():
    """
    Entry point for Yaralyzer when invoked as a script. Args are parsed from the command line
    and environment variables. See `yaralyze --help` for details.
    """
    args = YaralyzerConfig.parse_args()

    if args._standalone_mode:
        log_current_config(YaralyzerConfig)

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
        export_json(yaralyzer, args)

    if str(args.file_to_scan_path).lower().endswith('pdf'):
        log_console.print(PDFALYZER_MSG_TXT)

    # Drop into interactive shell if requested
    if args.interact:
        code.interact(local=locals())
