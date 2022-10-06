import code
from os import environ, getcwd, path

from dotenv import load_dotenv

# load_dotenv() should be called as soon as possible (before parsing local classes) but not for pytest
if not environ.get('INVOKED_BY_PYTEST', False):
    for dotenv_file in [path.join(dir, '.yaralyzer') for dir in [getcwd(), path.expanduser('~')]]:
        if path.exists(dotenv_file):
            load_dotenv(dotenv_path=dotenv_file)
            break

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.file_export import invoke_rich_export
from yaralyzer.output.rich_console import console
from yaralyzer.util.argument_parser import get_export_basepath, parse_arguments
from yaralyzer.util.logging import log
from yaralyzer.yaralyzer import Yaralyzer


def yaralyze():
    args = parse_arguments()
    output_basepath = None

    if args.yara_rules_files:
        yaralyzer = Yaralyzer.for_rules_files(args.yara_rules_files, args.file_to_scan_path)
    elif args.yara_rules_dirs:
        yaralyzer = Yaralyzer.for_rules_dirs(args.yara_rules_dirs, args.file_to_scan_path)
    elif args.yara_patterns:
        yaralyzer = Yaralyzer.for_patterns(
            args.yara_patterns,
            args.file_to_scan_path,
            regex_modifier=args.regex_modifier)
    else:
        raise RuntimeError("No pattern or YARA file to scan against.")

    if args.output_dir:
        output_basepath = get_export_basepath(args, yaralyzer)
        console.print(f"Will render yaralyzer data to '{output_basepath}'...", style='yellow')
        console.record = True

    yaralyzer.yaralyze()

    if args.export_txt:
        invoke_rich_export(console.save_text, output_basepath)

    if args.export_html:
        invoke_rich_export(console.save_html, output_basepath)

    if args.export_svg:
        invoke_rich_export(console.save_svg, output_basepath)

    # Drop into interactive shell if requested
    if args.interact:
        code.interact(local=locals())
