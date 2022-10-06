from subprocess import CalledProcessError, check_output

from tests.test_yaralyze import assert_output_line_count


def test_yaralyzer_show_color_theme():
    assert_output_line_count(['yaralyzer_show_color_theme'], 10)
