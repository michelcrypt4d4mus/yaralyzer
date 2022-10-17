"""
Tests for invoking yaralyze script from shell.
"""
from functools import partial
from math import isclose
from os import environ, path, remove
from subprocess import CalledProcessError, check_output

import pytest

from yaralyzer.config import YARALYZE
from yaralyzer.helpers.file_helper import files_in_dir
from yaralyzer.helpers.string_helper import line_count
from yaralyzer.output.rich_console import console
from tests.test_yaralyzer import CLOSENESS_THRESHOLD, EXPECTED_LINES
from tests.yara.test_yara_rule_builder import HEX_STRING


# Asking for help screen is a good canary test... proves code compiles, at least.
def test_help_option():
    help_text = _run_with_args('-h')
    assert 'maximize-width' in help_text
    _assert_line_count_within_range(118, help_text)


def test_no_rule_args(il_tulipano_path):
    with pytest.raises(CalledProcessError):
        _run_with_args(il_tulipano_path)


def test_too_many_rule_args(il_tulipano_path, tulips_yara_path):
    with pytest.raises(CalledProcessError):
        _run_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-re', 'tulip')
    with pytest.raises(CalledProcessError):
        _run_with_args(il_tulipano_path, '-dir', tulips_yara_path, '-re', 'tulip')
    with pytest.raises(CalledProcessError):
        _run_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-dir', path.dirname(tulips_yara_path))
    with pytest.raises(CalledProcessError):
        _run_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-hex', HEX_STRING)


def test_yaralyze_with_files(il_tulipano_path, tulips_yara_path):
    """
    Check output of:
        yaralyze -Y tests/file_fixtures/tulips.yara tests/file_fixtures/il_tulipano_nero.txt
        yaralyze -dir tests/file_fixtures/ tests/file_fixtures/il_tulipano_nero.txt
    """
    test_line_count = partial(_assert_output_line_count_is_close, 948, il_tulipano_path)
    test_line_count('-Y', tulips_yara_path)
    test_line_count('-dir', path.dirname(tulips_yara_path))


def test_yaralyze_with_patterns(il_tulipano_path, binary_file_path, tulips_yara_regex):
    _assert_output_line_count_is_close(945, il_tulipano_path, '-re', tulips_yara_regex)
    _assert_output_line_count_is_close(90, binary_file_path, '-re', '3Hl0')
    _assert_output_line_count_is_close(96, binary_file_path, '-hex', HEX_STRING)


def test_file_export(binary_file_path, tulips_yara_path, tmp_dir):
    _run_with_args(binary_file_path, '-Y', tulips_yara_path, '-svg', '-html', '-txt', '-out', tmp_dir)
    rendered_files = files_in_dir(tmp_dir)
    assert len(rendered_files) == 3
    file_sizes = [path.getsize(f) for f in rendered_files]
    _assert_array_is_close(sorted(file_sizes), [41677, 71115, 220090])

    for file in rendered_files:
        remove(file)


def _assert_array_is_close(_list1, _list2):
    for i, item in enumerate(_list1):
        if not isclose(item, _list2[i], rel_tol=CLOSENESS_THRESHOLD):
            assert False, f"File size of {item} too far from {_list2[i]}"


def _assert_output_line_count_is_close(expected_line_count: int, file_to_scan: str, *args) -> None:
    output_line_count = line_count(_run_with_args(file_to_scan, *args))
    assert isclose(expected_line_count, output_line_count, rel_tol=CLOSENESS_THRESHOLD)


def _run_with_args(file_to_scan, *args) -> str:
    """check_output() technically returns bytes so we decode before returning STDOUT output"""
    return check_output([YARALYZE, file_to_scan, *args], env=environ).decode()


def _assert_line_count_within_range(expected_line_count, text):
    lines_in_text = line_count(text)

    if not isclose(expected_line_count, lines_in_text, rel_tol=CLOSENESS_THRESHOLD):
        console.print(text)
        raise AssertionError(f"Expected {line_count} +/- but found {lines_in_text}")
