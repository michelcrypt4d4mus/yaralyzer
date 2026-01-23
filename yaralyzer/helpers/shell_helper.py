"""
Utility methods used by pytest both here and in Pdfalyzer.
"""
import json
import logging
import re
import shutil
from os import environ
from pathlib import Path
from subprocess import run

import pytest

from yaralyzer.helpers.env_helper import should_rebuild_fixtures
from yaralyzer.helpers.file_helper import load_file, relative_path
from yaralyzer.helpers.string_helper import strip_ansi_colors
from yaralyzer.output.rich_console import console
from yaralyzer.util.logging import log, log_bigly, shell_command_log_str

WROTE_TO_FILE_REGEX = re.compile(r"Wrote '(.*)' in [\d.]+ seconds")


def compare_export_to_file(
        cmd: list[str],
        against_dir: Path,
        ignorable_args: list[str] | None = None,
    ) -> None:
    """Compare the output of running a shell command to an existing file in 'against dir'."""
    result = run(cmd, capture_output=True, env=environ)
    stderr = strip_ansi_colors(result.stderr.decode())
    output_logs = shell_command_log_str(cmd, result, ignore_args=ignorable_args)
    log.error(output_logs)
    assert result.returncode == 0, f"Bad return code {result.returncode}, {output_logs}"
    wrote_to_match = WROTE_TO_FILE_REGEX.search(stderr)
    assert wrote_to_match, f"Could not find 'wrote to file' msg in stderr:\n\n{stderr}"
    written_file_path = relative_path(Path(wrote_to_match.group(1)))
    assert written_file_path.exists(), f"'{written_file_path}' does not exist, {output_logs}"
    fixture_path = relative_path(against_dir.joinpath(written_file_path.name))

    if should_rebuild_fixtures():
        log.warning(f"\nOverwriting fixture '{fixture_path}'\n   with contents of '{written_file_path}'")
        shutil.move(written_file_path, fixture_path)
        return

    assert fixture_path.exists()
    assert load_file(fixture_path) == load_file(written_file_path)
