import time
from os import path

from rich.terminal_theme import TerminalTheme

from yaralyzer.util.logging import log_and_print

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

def invoke_rich_export(export_method, output_file_basepath) -> str:
    """
    Announce the export, perform the export, announce completion.
    export_method is a Rich.console.save_blah() method, output_file_path is file path w/no extname.
    Returns the path to path data was exported to.
    """
    method_name = export_method.__name__
    extname = 'txt' if method_name == 'save_text' else method_name.split('_')[-1]
    output_file_path = f"{output_file_basepath}.{extname}"

    if method_name not in _EXPORT_KWARGS:
        raise RuntimeError(f"{method_name} is not a valid Rich.console export method!")

    kwargs = _EXPORT_KWARGS[method_name].copy()
    kwargs.update({'clear': False})

    if 'svg' in method_name:
        kwargs.update({'title': path.basename(output_file_path) })

    # Invoke it
    log_and_print(f"Invoking Rich.console.{method_name}('{output_file_path}') with kwargs: '{kwargs}'...")
    start_time = time.perf_counter()
    export_method(output_file_path, **kwargs)
    elapsed_time = time.perf_counter() - start_time
    log_and_print(f"'{output_file_path}' written in {elapsed_time:02f} seconds")
    return output_file_path

