"""
Tests for invoking yaralyze script from shell.
"""
from math import isclose
from os import environ
from subprocess import check_output

from yaralyzer.config import YARALYZE
from yaralyzer.helpers.rich_text_helper import console
from yaralyzer.helpers.string_helper import line_count


# Asking for help screen is a good canary test... proves code compiles, at least.
def test_help_option():
    help_text = _run_with_args('-h')
    assert 'maximize-width' in help_text
    assert len(help_text) > 2000
    assert len(help_text.split('\n')) > 50


def test_yaralyze(il_tulipano_path, tulips_yara_path, tulips_yara_regex):
    # yaralyze -y tests/file_fixtures/tulips.yara tests/file_fixtures/il_tulipano_nero.txt
    with_yara_file_output = _run_with_args(il_tulipano_path, '-Y', tulips_yara_path)
    # yaralyze -r 'tulip.{1,2500}tulip' tests/file_fixtures/il_tulipano_nero.txt
    with_pattern_output = _run_with_args(il_tulipano_path, '-re', tulips_yara_regex)
    assert line_count(with_pattern_output) == line_count(with_yara_file_output)
    _assert_line_count_within_range(814, with_yara_file_output)


def _run_with_args(file_to_scan, *args) -> str:
    """check_output() technically returns bytes so we decode before returning STDOUT output"""
    return check_output([YARALYZE, file_to_scan, *args], env=environ).decode()


def _assert_line_count_within_range(line_count, text):
    lines_in_text = len(text.split("\n"))

    if not isclose(line_count, lines_in_text, rel_tol=0.1):
        console.print(text)
        raise AssertionError(f"Expected {line_count} +/- but found {lines_in_text}")
