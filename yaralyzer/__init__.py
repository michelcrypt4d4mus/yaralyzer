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
from yaralyzer.helpers.rich_text_helper import console, invoke_rich_export
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.logging import log, log_and_print
from yaralyzer.yaralyzer import Yaralyzer


def yaralyze():
    args = parse_arguments()

    if args.yara_rules_files:
        yaralyzer = Yaralyzer.for_rules_files(args.yara_rules_files, args.file_to_scan_path)
    elif args.yara_patterns:
        yaralyzer = Yaralyzer.for_patterns(
            args.yara_patterns,
            args.file_to_scan_path,
            regex_modifier=args.regex_modifier)
    elif args.yara_rules_dirs:
        yaralyzer = Yaralyzer.for_rules_dirs(args.yara_rules_dirs, args.file_to_scan_path)
    else:
        raise RuntimeError("No pattern or YARA file to scan against.")

    if args.output_dir:
        file_prefix = (args.file_prefix + '_') if args.file_prefix else ''
        args.output_basename =  f"{file_prefix}{yaralyzer}"
        args.output_basename += f"_maxdecode{YaralyzerConfig.MAX_DECODE_LENGTH}"
        args.output_basename += ('_' + args.file_suffix) if args.file_suffix else ''
        args.output_basepath = path.join(args.output_dir, args.output_basename + f"___yaralyzed_{args.invoked_at_str}")
        console.record = True
        print(f'Exporting yaralyzer data to {args.output_basepath}...')

    yaralyzer.yaralyze()

    if args.export_txt:
        invoke_rich_export(console.save_text, args.output_basepath)

    if args.export_html:
        invoke_rich_export(console.save_html, args.output_basepath)

    if args.export_svg:
        invoke_rich_export(console.save_svg, args.output_basepath)

    # Drop into interactive shell if requested
    if args.interact:
        code.interact(local=locals())
