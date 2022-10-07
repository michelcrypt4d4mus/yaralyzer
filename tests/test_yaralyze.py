"""
Tests for invoking yaralyze script from shell.
"""
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
    _assert_line_count_within_range(111, help_text)


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


def test_yaralyze(il_tulipano_path, tulips_yara_path):
    # yaralyze -y tests/file_fixtures/tulips.yara tests/file_fixtures/il_tulipano_nero.txt
    with_yara_file_output = _run_with_args(il_tulipano_path, '-Y', tulips_yara_path)
    # yaralyze -dir tests/file_fixtures/ tests/file_fixtures/il_tulipano_nero.txt
    with_dir_output = _run_with_args(il_tulipano_path, '-dir', path.dirname(tulips_yara_path))
    counts = [line_count(output) for output in [with_yara_file_output, with_dir_output]]

    for c in counts:
        assert isclose(c, EXPECTED_LINES, rel_tol=CLOSENESS_THRESHOLD), f"{c} is too far from {EXPECTED_LINES}"


def test_yaralyze_with_patterns(il_tulipano_path, binary_file_path, tulips_yara_regex):
    # yaralyze -r 'tulip.{1,2500}tulip' tests/file_fixtures/il_tulipano_nero.txt
    with_pattern_output = _run_with_args(il_tulipano_path, '-re', tulips_yara_regex)
    assert line_count(with_pattern_output) == 942
    with_pattern_output = _run_with_args(binary_file_path, '-re', '3Hl0')
    assert line_count(with_pattern_output) == 83
    with_pattern_output = _run_with_args(binary_file_path, '-hex', HEX_STRING)
    assert line_count(with_pattern_output) == 90


def test_file_export(binary_file_path, tulips_yara_path, tmp_dir):
    _run_with_args(binary_file_path, '-Y', tulips_yara_path, '-svg', '-html', '-txt', '-out', tmp_dir)
    rendered_files = files_in_dir(tmp_dir)
    assert len(rendered_files) == 3
    file_sizes = [path.getsize(f) for f in rendered_files]
    assert_array_is_close(sorted(file_sizes), [40867, 69127, 216719])

    for file in rendered_files:
        remove(file)


def assert_output_line_count(shell_cmd: list, expected_line_count: int):
    _assert_line_count_within_range(expected_line_count, check_output(shell_cmd).decode())


def _run_with_args(file_to_scan, *args) -> str:
    """check_output() technically returns bytes so we decode before returning STDOUT output"""
    return check_output([YARALYZE, file_to_scan, *args], env=environ).decode()


def _assert_line_count_within_range(line_count, text):
    lines_in_text = len(text.split("\n"))

    if not isclose(line_count, lines_in_text, rel_tol=CLOSENESS_THRESHOLD):
        console.print(text)
        raise AssertionError(f"Expected {line_count} +/- but found {lines_in_text}")

def assert_array_is_close(_list1, _list2):
    for i, item in enumerate(_list1):
        if not isclose(item, _list2[i], rel_tol=CLOSENESS_THRESHOLD):
            assert False, f"File size of {item} too far from {_list2[i]}"
