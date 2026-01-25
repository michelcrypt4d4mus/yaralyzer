from yaralyzer.util.helpers.shell_helper import WROTE_TO_FILE_REGEX
from yaralyzer.util.helpers.string_helper import strip_ansi_colors
from yaralyzer.util.logging import log_file_export, log_console


def test_log_file_export(tmp_dir):
    with log_console.capture() as capture:
        with log_file_export(tmp_dir.joinpath('illmatic.txt')) as output_path:
            with open(output_path, 'wt') as outfile:
                outfile.write("world is yours")

    captured_text = strip_ansi_colors(capture.get())
    assert bool(WROTE_TO_FILE_REGEX.search(captured_text))
