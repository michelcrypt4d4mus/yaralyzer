"""
Functions to export Yaralyzer results to various file formats.
"""
from argparse import Namespace
import json
from pathlib import Path
from subprocess import CalledProcessError
from typing import Callable

from yaralyzer.output.theme import YARALYZER_TERMINAL_THEME
from yaralyzer.util.constants import INKSCAPE, INKSCAPE_URL
from yaralyzer.util.logging import log, log_console, log_file_export
from yaralyzer.util.helpers.env_helper import is_cairosvg_installed
from yaralyzer.util.helpers.shell_helper import ShellResult, get_inkscape_version, safe_args
from yaralyzer.yaralyzer import Yaralyzer

CAIROSVG_WARNING_MSG = f"PNG images rendered by CairoSVG may contain issues, especially with tables. " \
                       f"CairoSVG crashes are also not unheard of. " \
                       f"Consider installing {INKSCAPE.title()} if you plan to export a lot of images.\n" \
                       f"{INKSCAPE_URL}"

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


def export_json(yaralyzer: Yaralyzer, args: Namespace) -> Path:
    """
    Export YARA scan results to JSON.

    Args:
        yaralyzer (Yaralyzer): The `Yaralyzer` object containing the results to export.
        export_basepath (Path | None, Optional): Base path to write output to. Should have no file extension.

    Returns:
        Path: File path data was exported to.
    """
    json_export_path = Path(f"{args._export_basepath}.json")

    with log_file_export(json_export_path):
        matches_data = [m.to_json() for m, _decoder in yaralyzer.match_iterator()]

        with open(json_export_path, 'w') as f:
            json.dump(matches_data, f, indent=4)
            return json_export_path


def invoke_rich_export(export_method: Callable, args: Namespace) -> None:
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

    if method_name not in _EXPORT_KWARGS:
        raise RuntimeError(f"{method_name} is not a valid Rich.console export method!")

    kwargs = _EXPORT_KWARGS[method_name].copy()
    kwargs.update({'clear': False})
    is_svg_export = 'svg' in method_name

    if is_svg_export:
        kwargs.update({'title': export_file_path.name})

    # Invoke the export method
    with log_file_export(export_file_path):
        log.info(f"Invoking rich.console.{method_name}('{export_file_path}') with kwargs: '{kwargs}'...")
        export_method(export_file_path, **kwargs)

    # PNGs are rendered from SVGs
    if is_svg_export and args.export_png:
        with log_file_export(export_file_path.parent.joinpath(export_file_path.stem + '.png')) as png_path:
            render_png(export_file_path, png_path, args)


def render_png(svg_path: Path, png_path: Path, args: Namespace) -> Path | None:
    """Turn the svg output into a png with Inkscape or cairosvg. Returns png path if successful."""
    try:
        if get_inkscape_version():
            try:
                return _render_png_with_inkscape(svg_path, png_path)
            except (CalledProcessError, FileNotFoundError) as e:
                error_msg = f"Failed to render png with {INKSCAPE}! ({e})"

                if is_cairosvg_installed():
                    log.error(error_msg + f"\n\nFalling back to using cairosvg. Rendered image may me imperfect.")
                else:
                    log.error(error_msg + f"\n\ncairosvg not available to fallback to.")
                    raise e

        return _render_png_with_cairosvg(svg_path, png_path)
    except Exception as e:
        log.error(f"Failed to render png! ({e})")
    finally:
        if not args._keep_exported_svg:
            log.info(f"Removing intermediate SVG file '{svg_path}'...")
            svg_path.unlink()


def _render_png_with_inkscape(svg_path: Path, png_path) -> Path | None:
    log_console.print(f"Rendering .png image with {INKSCAPE}...", highlight=False, style='dim')
    inkscape_cmd = safe_args([INKSCAPE, f'--export-filename={png_path}', svg_path])
    ShellResult.from_cmd(inkscape_cmd, verify_success=True)
    return png_path


def _render_png_with_cairosvg(svg_path: Path, png_path) -> Path:
    log.warning(CAIROSVG_WARNING_MSG)
    import cairosvg
    cairosvg.svg2png(url=str(svg_path), write_to=str(png_path))
    return png_path
