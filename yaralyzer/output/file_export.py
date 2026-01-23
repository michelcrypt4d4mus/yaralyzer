"""
Functions to export Yaralyzer results to various file formats.
"""
import json
import time
from pathlib import Path
from typing import Callable, Optional

from rich.terminal_theme import TerminalTheme

from yaralyzer.helpers.file_helper import relative_path
from yaralyzer.util.logging import log, log_and_print
from yaralyzer.yaralyzer import Yaralyzer

WRITE_STYLE = 'grey46'

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


def export_json(yaralyzer: Yaralyzer, output_basepath: str | None = None) -> Path:
    """
    Export YARA scan results to JSON.

    Args:
        yaralyzer (Yaralyzer): The `Yaralyzer` object containing the results to export.
        output_basepath (Optional[str]): Base path to write output to. Should have no file extension.

    Returns:
        Path: File data was exported to.
    """
    output_path = Path(f"{output_basepath or 'yara_matches'}.json")
    matches_data = [match.to_json() for match, _decoder in yaralyzer.match_iterator()]

    with open(output_path, 'w') as f:
        json.dump(matches_data, f, indent=4)

    log_and_print(f"YARA matches exported to JSON file: '{relative_path(output_path)}'", style=WRITE_STYLE)
    return output_path


def invoke_rich_export(export_method: Callable, output_file_basepath: str | Path) -> Path:
    """
    Announce the export, perform the export, and announce completion.

    Args:
        export_method (Callable): Usually a `Rich.console.save_whatever()` method
        output_file_basepath (str): Path to write output to. Should have no file extension.

    Returns:
        Path: Path data was exported to.
    """
    method_name = export_method.__name__
    extname = 'txt' if method_name == 'save_text' else method_name.split('_')[-1]
    output_file_path = Path(f"{output_file_basepath}.{extname}")

    if method_name not in _EXPORT_KWARGS:
        raise RuntimeError(f"{method_name} is not a valid Rich.console export method!")

    kwargs = _EXPORT_KWARGS[method_name].copy()
    kwargs.update({'clear': False})

    if 'svg' in method_name:
        kwargs.update({'title': output_file_path.name})

    # Invoke it
    log.info(f"Invoking rich.console.{method_name}('{output_file_path}') with kwargs: '{kwargs}'...")
    start_time = time.perf_counter()
    export_method(output_file_path, **kwargs)
    write_time = time.perf_counter() - start_time
    log_and_print(f"\nWrote '{relative_path(output_file_path)}' in {write_time:.2f} seconds", style=WRITE_STYLE)
    return output_file_path
