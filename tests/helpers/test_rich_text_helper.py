from subprocess import check_output

from tests.test_yaralyze import _assert_line_count_within_range


def test_yaralyzer_show_color_theme():
    _assert_output_line_count(['yaralyzer_show_color_theme'], 12)


def _assert_output_line_count(shell_cmd: list, expected_line_count: int):
    _assert_line_count_within_range(expected_line_count, check_output(shell_cmd).decode())
