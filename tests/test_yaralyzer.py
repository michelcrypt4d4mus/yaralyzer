"""
Tests for the Yaralyzer class itself.
"""
from math import isclose
from os.path import dirname
from typing import Tuple

import pytest

from yaralyzer.helpers.string_helper import line_count
from yaralyzer.output.rich_console import console
from yaralyzer.yara.yara_rule_builder import REGEX
from yaralyzer.yaralyzer import Yaralyzer

CLOSENESS_THRESHOLD = 0.05
EXPECTED_LINES = 1060


def test_filename_string(a_yaralyzer):
    assert a_yaralyzer._filename_string() == 'il_tulipano_nero.txt_scanned_with_tulips.yara'


def test_yaralyzer_with_files(il_tulipano_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path))
    assert result[0], result[1]

    with pytest.raises(FileNotFoundError):
        Yaralyzer.for_rules_files(['nonexistent.file.yara'], il_tulipano_path)


def test_yaralyzer_with_patterns(il_tulipano_path, tulips_yara_regex):
    result = _check_output_linecount(
        Yaralyzer.for_patterns([tulips_yara_regex], REGEX, il_tulipano_path),
        EXPECTED_LINES)

    assert result[0], result[1]


def test_yaralyzer_for_rules_dir(il_tulipano_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_dirs([dirname(tulips_yara_path)], il_tulipano_path))
    assert result[0], result[1]

    with pytest.raises(FileNotFoundError):
        Yaralyzer.for_rules_dirs(['nonexistent/dir/'], il_tulipano_path)


def test_hex_rules(binary_file_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_files([tulips_yara_path], binary_file_path), 102)
    assert result[0], result[1]


def _check_output_linecount(yaralzyer: Yaralyzer, expected_line_count: int = EXPECTED_LINES) -> Tuple[bool, str]:
    with console.capture() as capture:
        yaralzyer.yaralyze()

    _lines_count = line_count(capture.get())

    return (
        isclose(line_count(capture.get()), expected_line_count, rel_tol=CLOSENESS_THRESHOLD),
        f"{_lines_count} is too far from {expected_line_count}"
    )
