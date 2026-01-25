"""
Tests for invoking yaralyze script from shell (NOT for Yaralyzer() class directly - those tests
are over in test_yaralyzer.py)
"""
import json
import logging
import re
from math import isclose
from pathlib import Path
from subprocess import CalledProcessError
from sys import version_info

import pytest

from yaralyzer.output.console import console
from yaralyzer.util.constants import NO_TIMESTAMPS_OPTION, YARALYZE
from yaralyzer.util.helpers.file_helper import file_size, load_file, relative_path
from yaralyzer.util.helpers.shell_helper import ShellResult, safe_args
from yaralyzer.util.helpers.string_helper import line_count
from yaralyzer.util.logging import log, log_bigly

from .conftest import MAXDECODE_SUFFIX, RENDERED_FIXTURES_DIR, TMP_DIR
from .test_yaralyzer import CLOSENESS_THRESHOLD
from .yara.test_yara_rule_builder import HEX_STRING

DEFAULT_CLI_ARGS = [NO_TIMESTAMPS_OPTION, '--output-dir', relative_path(TMP_DIR)]
EXPORT_TEXT_ARGS = DEFAULT_CLI_ARGS + ['-txt']


# Asking for help screen is a good canary test... proves code compiles, at least.
def test_help_option():
    help_text = _yaralyze_with_args('-h').stdout
    assert all(word in help_text for word in ['.yaralyzer', 'maximize-width', 'API docs', 'http'])
    assert 'pdfalyzer' not in help_text.lower()
    _assert_line_count_within_range(140, help_text, 0.2)


def test_no_rule_args(il_tulipano_path):
    with pytest.raises(CalledProcessError):
        _yaralyze_with_args(il_tulipano_path)


def test_too_many_rule_args(il_tulipano_path, tulips_yara_path):
    with pytest.raises(CalledProcessError):
        _yaralyze_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-re', 'tulip')
    with pytest.raises(CalledProcessError):
        _yaralyze_with_args(il_tulipano_path, '-dir', tulips_yara_path, '-re', 'tulip')
    with pytest.raises(CalledProcessError):
        _yaralyze_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-dir', tulips_yara_path.parent)
    with pytest.raises(CalledProcessError):
        _yaralyze_with_args(il_tulipano_path, '-Y', tulips_yara_path, '-hex', HEX_STRING)


@pytest.mark.skipif(version_info < (3, 11), reason="currently failing on python 3.10 (slight UTF-16 decode mismatch)")
def test_yaralyze_with_rule_files(il_tulipano_path, tulips_yara_path):
    # yaralyze -Y tests/fixtures/yara_rules/tulips.yara tests/fixtures/il_tulipano_nero.txt
    _compare_exported_txt_to_fixture(il_tulipano_path, '-Y', tulips_yara_path)
    # yaralyze -dir tests/fixtures/ tests/fixtures/il_tulipano_nero.txt
    _compare_exported_txt_to_fixture(il_tulipano_path, '-dir', tulips_yara_path.parent)


@pytest.mark.skipif(version_info < (3, 11), reason="currently failing on python 3.10 (slight UTF-16 decode mismatch)")
def test_yaralyze_with_patterns(il_tulipano_path, binary_file_path, tulips_yara_pattern):
    _compare_exported_txt_to_fixture(il_tulipano_path, '-re', tulips_yara_pattern)
    _compare_exported_txt_to_fixture(binary_file_path, '-re', '3Hl0')
    _compare_exported_txt_to_fixture(binary_file_path, '-hex', HEX_STRING)


def test_multi_export(binary_file_path, tulips_yara_path, tmp_dir):
    result = _compare_exported_txt_to_fixture(binary_file_path, '-Y', tulips_yara_path, '-html', '-json', '-svg')
    assert len(result.exported_file_paths()) == 4

    # Check JSON
    json_export_path = next(f for f in result.exported_file_paths() if str(f).endswith('json'))
    json_data = json.loads(load_file(json_export_path))  # Ensure JSON is valid
    assert isinstance(json_data, list), "JSON data should be a list of matches"
    assert len(json_data) == 2, "JSON data should not be empty"
    first_match = json_data[0]
    assert first_match.get('label') == "There_Will_Be_Tulips: $tulip", "First match should have correct 'label'"
    assert first_match.get('match_length') == 8, "First match should have 'length' key"
    assert first_match.get('ordinal') == 1, "First match should have 'ordinal' value of 1"
    assert first_match.get('start_idx') == 120512, "First match should have 'start_idx' value of 120512"
    assert len(first_match.get('matched_bytes')) == 16, "First match should have 16 'matched_bytes'"
    assert len(first_match.get('surrounding_bytes')) == 272, "First match should have 272 'surrounding_bytes'"


def test_png_export(il_tulipano_path, tmp_dir):
    regex = 'pregiatissimi'
    cmd = _yaralyze_shell_cmd(il_tulipano_path, '-re', regex, '-png')
    expected_basepath = f'{il_tulipano_path.name}_scanned_with_{regex}{MAXDECODE_SUFFIX}'
    result = ShellResult.from_cmd(cmd)
    tmp_png_path = tmp_dir.joinpath(f'{expected_basepath}.png')
    assert result.last_exported_file_path().resolve() == tmp_png_path
    assert tmp_png_path.exists(), f"PNG does not exist! '{tmp_png_path}'"
    assert file_size(tmp_png_path) > 500_000
    assert not tmp_dir.joinpath(f"{expected_basepath}.svg").exists()


def _yaralyze_with_args(file_to_scan: str | Path, *args) -> ShellResult:
    cmd = _yaralyze_shell_cmd(file_to_scan, *args)
    shell_result = ShellResult.from_cmd(cmd)

    try:
        shell_result.result.check_returncode()
        return shell_result
    except CalledProcessError as e:
        cmd = ' '.join([str(e) for e in e.cmd])
        raise CalledProcessError(e.returncode, shell_result.invocation_str, e.output, e.stderr)


def _assert_line_count_within_range(expected_line_count: int, text: str, rel_tol: float = CLOSENESS_THRESHOLD):
    lines_in_text = line_count(text)

    if not isclose(expected_line_count, lines_in_text, rel_tol=rel_tol):
        console.print(text)
        raise AssertionError(f"Expected {expected_line_count} +/- but found {lines_in_text}")


def _compare_exported_txt_to_fixture(file_to_scan: str | Path, *args):
    """
    Compare the output of running yaralyze for a given file/arg combo to prerecorded fixture data.
    'fixture_name' arg should be used in cases where tests with different filename outputs
    can be compared against the same fixture file.
    """
    cmd = _yaralyze_shell_cmd(file_to_scan, *[*args, '-txt'])
    return ShellResult.run_and_compare_exported_files_to_existing(cmd, RENDERED_FIXTURES_DIR, DEFAULT_CLI_ARGS)


def _yaralyze_shell_cmd(file_path: str | Path, *args) -> list[str]:
    """Appends DEFAULT_CLI_ARGS."""
    return [YARALYZE] + safe_args([file_path, *args, *DEFAULT_CLI_ARGS])
