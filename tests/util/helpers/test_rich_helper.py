from yaralyzer.util.constants import YARALYZER
from yaralyzer.util.helpers.shell_helper import ShellResult


def test_yaralyzer_show_color_theme():
    result = ShellResult.from_cmd('yaralyzer_show_color_theme', verify_success=True)
    assert 'bytes.decoded' in result.stdout_stripped
    assert YARALYZER in result.stdout_stripped.lower()
    assert 10 < len(result.stdout_lines) < 20
