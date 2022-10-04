"""
Tests for the Yaralyzer class.
"""
from os.path import dirname

from yaralyzer.helpers.rich_text_helper import console
from yaralyzer.helpers.string_helper import line_count
from yaralyzer.yaralyzer import Yaralyzer

EXPECTED_LINES = 814


def test_yaralyzer_with_files(il_tulipano_path, tulips_yara_path):
    _test_yaralyze(Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path))


def test_yaralyzer_with_patterns(il_tulipano_path, tulips_yara_regex):
    _test_yaralyze(Yaralyzer.for_patterns([tulips_yara_regex], il_tulipano_path))


def test_yaralyzer_for_rules_dir(il_tulipano_path, tulips_yara_regex):
    _test_yaralyze(Yaralyzer.for_rules_dir(dirname(il_tulipano_path), il_tulipano_path))


def _test_yaralyze(yaralzyer: Yaralyzer) -> None:
    with console.capture() as capture:
        yaralzyer.yaralyze()

    assert line_count(capture.get()) == EXPECTED_LINES
