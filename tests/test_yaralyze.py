"""
Tests for invoking yaralyze script from shell (NOT for Yaralyzer() class directly - those tests
are over in test_yaralyzer.py)
"""
import json
from functools import partial
from math import isclose
from os import environ, path
from subprocess import CalledProcessError, check_output

import pytest

from tests.test_yaralyzer import CLOSENESS_THRESHOLD
from tests.yara.test_yara_rule_builder import HEX_STRING
from yaralyzer.helpers.file_helper import files_in_dir, load_file
from yaralyzer.helpers.string_helper import line_count
from yaralyzer.output.rich_console import console
from yaralyzer.util.constants import YARALYZE


# Asking for help screen is a good canary test... proves code compiles, at least.
def test_help_option():
    help_text = _run_with_args('-h')
    assert 'maximize-width' in help_text
    _assert_line_count_within_range(131, help_text)


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
    test_line_count = partial(_assert_output_line_count_is_close, 1048, il_tulipano_path)
    test_line_count('-Y', tulips_yara_path)
    test_line_count('-dir', path.dirname(tulips_yara_path))


def test_yaralyze_with_patterns(il_tulipano_path, binary_file_path, tulips_yara_regex):
    _assert_output_line_count_is_close(1044, il_tulipano_path, '-re', tulips_yara_regex)
    _assert_output_line_count_is_close(90, binary_file_path, '-re', '3Hl0')
    _assert_output_line_count_is_close(96, binary_file_path, '-hex', HEX_STRING)


def test_file_export(binary_file_path, tulips_yara_path, tmp_dir):
    _run_with_args(binary_file_path, '-Y', tulips_yara_path, '-html', '-json', '-svg', '-txt', '-out', tmp_dir)
    rendered_files = files_in_dir(tmp_dir)
    assert len(rendered_files) == 4
    file_sizes = [path.getsize(f) for f in rendered_files]
    _assert_array_is_close(sorted(file_sizes), [1182, 45179, 78781, 243312])

    for file in rendered_files:
        if file.name.endswith('.json'):
            json_data = json.loads(load_file(file))  # Ensure JSON is valid
            assert isinstance(json_data, list), "JSON data should be a list of matches"
            assert len(json_data) == 2, "JSON data should not be empty"

            first_match = json_data[0]
            assert first_match.get('label') == "There_Will_Be_Tulips: $tulip", "First match should have correct 'label'"
            assert first_match.get('match_length') == 8, "First match should have 'length' key"
            assert first_match.get('ordinal') == 1, "First match should have 'ordinal' value of 1"
            assert first_match.get('start_idx') == 120512, "First match should have 'start_idx' value of 120512"
            assert len(first_match.get('matched_bytes')) == 16, "First match should have 16 'matched_bytes'"
            assert len(first_match.get('surrounding_bytes')) == 272, "First match should have 272 'surrounding_bytes'"


def _assert_array_is_close(_list1, _list2):
    for i, item in enumerate(_list1):
        if not isclose(item, _list2[i], rel_tol=CLOSENESS_THRESHOLD):
            assert False, f"File size of {item} too far from {_list2[i]}"


def _assert_output_line_count_is_close(expected_line_count: int, file_to_scan: str, *args) -> None:
    output_line_count = line_count(_run_with_args(file_to_scan, *args))
    assert isclose(expected_line_count, output_line_count, rel_tol=CLOSENESS_THRESHOLD)


def _run_with_args(file_to_scan, *args) -> str:
    """check_output() technically returns bytes so we decode before returning STDOUT output"""
    try:
        output = check_output([YARALYZE, file_to_scan, *args], env=environ).decode()
        # print(output)
        return output
    except CalledProcessError as e:
        cmd = ' '.join([str(e) for e in e.cmd])
        raise CalledProcessError(e.returncode, cmd, e.output, e.stderr)


def _assert_line_count_within_range(expected_line_count: int, text: str, rel_tol: float = CLOSENESS_THRESHOLD):
    lines_in_text = line_count(text)

    if not isclose(expected_line_count, lines_in_text, rel_tol=rel_tol):
        console.print(text)
        raise AssertionError(f"Expected {expected_line_count} +/- but found {lines_in_text}")
