"""
Tests for the Yaralyzer class itself.
"""
from os.path import dirname

from yaralyzer.helpers.string_helper import line_count
from yaralyzer.output.rich_console import console
from yaralyzer.yaralyzer import Yaralyzer

EXPECTED_LINES = 817


def test_yaralyzer_with_files(il_tulipano_path, tulips_yara_path):
    _test_yaralyzer(Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path))


def test_yaralyzer_with_patterns(il_tulipano_path, tulips_yara_regex):
    _test_yaralyzer(Yaralyzer.for_patterns([tulips_yara_regex], il_tulipano_path), 814)


def test_yaralyzer_for_rules_dir(il_tulipano_path):
    _test_yaralyzer(Yaralyzer.for_rules_dirs([dirname(il_tulipano_path)], il_tulipano_path))


def test_hex_rules(binary_file_path, tulips_yara_path):
    _test_yaralyzer(Yaralyzer.for_rules_files([tulips_yara_path], binary_file_path), 79)



def _test_yaralyzer(yaralzyer: Yaralyzer, expected_line_count: int = EXPECTED_LINES) -> None:
    with console.capture() as capture:
        yaralzyer.yaralyze()

    assert line_count(capture.get()) == expected_line_count
