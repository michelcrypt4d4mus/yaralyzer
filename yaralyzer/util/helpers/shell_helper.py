"""
Utility methods used by pytest both here and in Pdfalyzer.
"""
import logging
import re
import shutil
from os import environ
from pathlib import Path
from subprocess import CompletedProcess, run

from yaralyzer.util.helpers.collections_helper import listify
from yaralyzer.util.helpers.env_helper import is_env_var_set_and_not_false
from yaralyzer.util.helpers.file_helper import load_file, relative_path
from yaralyzer.util.helpers.string_helper import strip_ansi_colors
from yaralyzer.util.logging import log, log_bigly, shell_command_log_str

PYTEST_REBUILD_FIXTURES_ENV_VAR = 'PYTEST_REBUILD_FIXTURES'
WROTE_TO_FILE_REGEX = re.compile(r"Wrote '(.*)' in [\d.]+ seconds")


def run_cmd_and_compare_exported_file_to_existing(
        cmd: list[str],
        against_dir: Path,
        ignorable_args: list[str] | None = None,
    ) -> None:
    """
    Compare the output of running a shell command to an existing file in `against_dir`.
    The command should write to the same filename, just in a different dir.

    Args:
        cmd (list[str]): The command to run, broken up into individual strings.
        against_dir (Path): Dir where the file to compare against exists already.
        ignorable_args (list[str], optional): Don't log these args if they exist in `cmd`.
    """
    result = run(cmd, capture_output=True, env=environ, text=True)
    compare_exported_file_to_existing(result, against_dir, ignorable_args)


def compare_exported_file_to_existing(
        result: CompletedProcess,
        against_dir: Path,
        ignorable_args: list[str] | None = None,
    ) -> None:
    output_logs = shell_command_log_str(result, ignore_args=ignorable_args)
    log.debug(output_logs)
    assert result.returncode == 0, f"Bad return code {result.returncode}, {output_logs}"

    stderr_output = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
    new_file_path = extract_written_file_path(stderr_output)
    assert new_file_path.exists(), f"'{new_file_path}' does not exist, {output_logs}"
    fixture_path = relative_path(against_dir.joinpath(new_file_path.name))

    if should_rebuild_fixtures():
        log.warning(f"\nOverwriting fixture '{fixture_path}'\n   with contents of '{new_file_path}'")
        shutil.move(new_file_path, fixture_path)
        return

    assert fixture_path.exists()
    fixture_data = load_file(fixture_path)
    new_data = load_file(new_file_path)
    assert new_data == fixture_data


def extract_written_file_path(stderr_output: str) -> Path:
    """Finds the last match."""
    stderr_output = strip_ansi_colors(stderr_output)
    wrote_to_match = None

    for match in WROTE_TO_FILE_REGEX.finditer(stderr_output):
        wrote_to_match = match

    assert wrote_to_match, f"Could not find 'wrote to file' msg in stderr:\n\n{stderr_output}"
    return relative_path(Path(wrote_to_match.group(1)))


def safe_args(cmd: str | list) -> list[str]:
    """Make sure everything is a string and not, for instance, a `Path`."""
    args = cmd.split() if isinstance(cmd, str) else cmd
    return [str(arg) for arg in args]


def should_rebuild_fixtures() -> bool:
    """True if pytest should overwrite fixture data with new output instead of comparing."""
    return is_env_var_set_and_not_false(PYTEST_REBUILD_FIXTURES_ENV_VAR)
