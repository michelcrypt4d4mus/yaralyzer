"""
Functions to export Yaralyzer results to various file formats.
"""
from argparse import Namespace
import json
import re
import time
from pathlib import Path
from subprocess import CalledProcessError, check_output, run
from typing import Callable

from rich.terminal_theme import TerminalTheme

from yaralyzer.util.constants import INKSCAPE_URL
from yaralyzer.util.logging import WRITE_STYLE, invocation_str, log, log_console, log_and_print, log_file_write
from yaralyzer.util.helpers.env_helper import INKSCAPE, get_inkscape_version, is_cairosvg_installed
from yaralyzer.util.helpers.file_helper import relative_path
from yaralyzer.util.helpers.shell_helper import safe_args
from yaralyzer.yaralyzer import Yaralyzer

CAIROSVG_WARNING_MSG = f"PNG images rendered by CairoSVG may contain issues, especially with tables. " \
                       f"CairoSVG crashes are also not unheard of.\n" \
                       f"Consider installing {INKSCAPE.title()} if you plan to export a lot of images.\n" \
                       f"{INKSCAPE_URL}"

# TerminalThemes are used when saving SVGS. This one just swaps white for black in DEFAULT_TERMINAL_THEME
YARALYZER_TERMINAL_THEME = TerminalTheme(
    (0, 0, 0),
    (255, 255, 255),
    [
        (0, 0, 0),
        (128, 0, 0),
        (0, 128, 0),
        (128, 128, 0),
        (0, 0, 128),
        (128, 0, 128),
        (0, 128, 128),
        (192, 192, 192),
    ],
    [
        (128, 128, 128),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (0, 0, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ],
)

# Keys are export function names, values are options we always want to use w/that export function
# Not meant for direct access; instead call invoke_rich_export().
_EXPORT_KWARGS = {
    'save_html': {
        'inline_styles': True,
        'theme': YARALYZER_TERMINAL_THEME,
    },
    'save_svg': {
        'theme': YARALYZER_TERMINAL_THEME,
    },
    'save_text': {
        'styles': True,
    },
}


def export_json(yaralyzer: Yaralyzer, export_basepath: Path | None = None) -> Path:
    """
    Export YARA scan results to JSON.

    Args:
        yaralyzer (Yaralyzer): The `Yaralyzer` object containing the results to export.
        export_basepath (Path | None, Optional): Base path to write output to. Should have no file extension.

    Returns:
        Path: File data was exported to.
    """
    json_export_path = Path(f"{export_basepath or 'yara_matches'}.json")
    matches_data = [match.to_json() for match, _decoder in yaralyzer.match_iterator()]

    with open(json_export_path, 'w') as f:
        json.dump(matches_data, f, indent=4)

    log_and_print(f"YARA matches exported to JSON file: '{relative_path(json_export_path)}'", style=WRITE_STYLE)
    return json_export_path


def invoke_rich_export(export_method: Callable, args: Namespace) -> Path:
    """
    Announce the export, perform the export, and announce completion.

    Args:
        export_method (Callable): Usually a `Rich.console.save_whatever()` method.
        args (Namespace, optional): Arguments parsed by ArgumeentParser.

    Returns:
        Path: Path data was exported to.
    """
    method_name = export_method.__name__
    extname = 'txt' if method_name == 'save_text' else method_name.split('_')[-1]
    export_file_path = Path(f"{args._export_basepath}.{extname}")
    export_png = False

    if method_name not in _EXPORT_KWARGS:
        raise RuntimeError(f"{method_name} is not a valid Rich.console export method!")

    kwargs = _EXPORT_KWARGS[method_name].copy()
    kwargs.update({'clear': False})

    if 'svg' in method_name:
        kwargs.update({'title': export_file_path.name})
        export_png = args and args.export_png

    # Invoke it
    log.info(f"Invoking rich.console.{method_name}('{export_file_path}') with kwargs: '{kwargs}'...")
    started_at = time.perf_counter()
    export_method(export_file_path, **kwargs)
    log_file_write(export_file_path, started_at)

    if export_png:
        png_path = render_png(export_file_path)

        if png_path and not args._svg_requested:
            log.warning(f"Removing intermediate PNG...")
            export_file_path.unlink()
            return png_path

    return export_file_path


def render_png(svg_path: Path) -> Path | None:
    """Turn the svg output into a png with Inkscape or cairosvg. Returns png path if successful."""
    started_at = time.perf_counter()
    inkscape_version = get_inkscape_version()
    png_path = svg_path.parent.joinpath(svg_path.stem + '.png')

    if inkscape_version:
        log_console.print(f"Rendering .png image with {INKSCAPE} {inkscape_version}...", highlight=False, style='dim')
        inkscape_cmd_args = safe_args([INKSCAPE, f'--export-filename={png_path}', svg_path])
        log.debug(f"Running inkscape cmd: {invocation_str(inkscape_cmd_args)}")

        try:
            check_output(inkscape_cmd_args)
            log_file_write(png_path, started_at)
            return png_path
        except (CalledProcessError, FileNotFoundError) as e:
            error_msg = f"Failed to render png with {INKSCAPE}! ({e})"

            if not is_cairosvg_installed():
                log.error(error_msg + f"\n\ncairosvg not available to fallback to.")
                return
            else:
                log.error(error_msg + f"\n\nFalling back to using cairosvg. Rendered image may me imperfect.")

    try:
        import cairosvg
        log.warning(CAIROSVG_WARNING_MSG)
        cairosvg.svg2png(url=str(svg_path), write_to=str(png_path))
        log_file_write(png_path, started_at)
        return png_path
    except Exception as e:
        log.error(f"Failed to render png with cairosvg! ({e})")
