"""
Tests for the Yaralyzer class itself.
"""
from contextlib import contextmanager
from copy import deepcopy
from math import isclose
from os.path import dirname
from pathlib import Path
from typing import Generator, Tuple

import pytest

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.console import console
from yaralyzer.util.helpers.env_helper import temporary_argv
from yaralyzer.util.helpers.shell_helper import safe_args
from yaralyzer.util.helpers.string_helper import line_count
from yaralyzer.yara.yara_rule_builder import REGEX
from yaralyzer.yaralyzer import Yaralyzer

from .conftest import MAXDECODE_SUFFIX, YARA_FIXTURES_DIR, YARALYZE_BASE_CMD
from .yara.test_yara_rule_builder import HEX_STRING

CLOSENESS_THRESHOLD = 0.05
EXPECTED_LINES = 1060


@contextmanager
def temporary_config(new_argv: list[str | Path]) -> Generator[None, None, None]:
    """Temporarily update `YaralyzerConfig` with the results of parsing a new `sys.argv`."""
    with temporary_argv(new_argv):
        old_args = deepcopy(YaralyzerConfig.args)
        YaralyzerConfig.parse_args()
        yield
        YaralyzerConfig._args = old_args


# A Yaralyzer
@pytest.fixture
def tulip_yaralyzer(il_tulipano_path, yaralyze_tulips_cmd, tulips_yara_path) -> Generator[Yaralyzer, None, None]:
    with temporary_config(yaralyze_tulips_cmd):
        yield Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path)


def test_export_basepath(tulip_yaralyzer, il_tulipano_path, yaralyze_tulips_cmd, tulips_yara_path, tulips_yara_pattern):
    expected_basename = f"{il_tulipano_path.name}_scanned_with_"

    def assert_filename(yaralyzer: Yaralyzer, filename: str) -> None:
        assert yaralyzer.export_basepath() == Path.cwd().joinpath(filename + MAXDECODE_SUFFIX)

    assert_filename(tulip_yaralyzer, expected_basename + f"{tulips_yara_path.name}")
    diralyzer = Yaralyzer.for_rules_dirs([YARA_FIXTURES_DIR], il_tulipano_path)
    assert_filename(diralyzer, expected_basename + f'pdf_rule.yara,{tulips_yara_path.name}')

    with temporary_config(yaralyze_tulips_cmd + ['--suppress-decodes-table']):
        assert_filename(tulip_yaralyzer, expected_basename + f"{tulips_yara_path.name}__suppress_decodes")

    with temporary_config(yaralyze_tulips_cmd + ['--file-prefix', 'nas']):
        assert_filename(tulip_yaralyzer, 'nas__' + expected_basename + f"{tulips_yara_path.name}")

    with temporary_config(yaralyze_tulips_cmd + ['--file-suffix', 'NAS']):
        expected_basename_with_suffix = f"{expected_basename}{tulips_yara_path.name}{MAXDECODE_SUFFIX}_NAS"
        assert tulip_yaralyzer.export_basepath() == Path.cwd().joinpath(expected_basename_with_suffix)

    # Regex
    regexalyzer = Yaralyzer.for_patterns([r"illmatic\s*by\s*nas"], 'regex', il_tulipano_path)
    assert_filename(regexalyzer, expected_basename + 'illmaticsbysnas')
    regexalyzer = Yaralyzer.for_patterns([tulips_yara_pattern], 'regex', il_tulipano_path)
    assert_filename(regexalyzer, expected_basename + 'tulip.1,2500tulip')
    # Hex
    hexalyzer = Yaralyzer.for_patterns([HEX_STRING], 'hex', il_tulipano_path)
    assert_filename(hexalyzer, expected_basename + 'e0_9a_3f_51_dd_25_ce_4c')


def test_hex_rules(binary_file_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_files([tulips_yara_path], binary_file_path), 102)
    assert result[0], result[1]


def test_yaralyzer_with_files(il_tulipano_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path))
    assert result[0], result[1]

    with pytest.raises(FileNotFoundError):
        Yaralyzer.for_rules_files(['nonexistent.file.yara'], il_tulipano_path)


def test_yaralyzer_with_patterns(il_tulipano_path, tulips_yara_pattern):
    result = _check_output_linecount(
        Yaralyzer.for_patterns([tulips_yara_pattern], REGEX, il_tulipano_path),
        EXPECTED_LINES
    )

    assert result[0], result[1]


def test_yaralyzer_for_rules_dir(il_tulipano_path, tulips_yara_path):
    result = _check_output_linecount(Yaralyzer.for_rules_dirs([dirname(tulips_yara_path)], il_tulipano_path))
    assert result[0], result[1]

    with pytest.raises(FileNotFoundError):
        Yaralyzer.for_rules_dirs(['nonexistent/dir/'], il_tulipano_path)


def _check_output_linecount(yaralzyer: Yaralyzer, expected_line_count: int = EXPECTED_LINES) -> Tuple[bool, str]:
    with console.capture() as capture:
        yaralzyer.yaralyze()

    _lines_count = line_count(capture.get())

    return (
        isclose(line_count(capture.get()), expected_line_count, rel_tol=CLOSENESS_THRESHOLD),
        f"{_lines_count} is too far from {expected_line_count}"
    )
