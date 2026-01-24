"""
Utility methods used by pytest both here and in Pdfalyzer.
"""
import logging
import re
import shutil
from dataclasses import dataclass, field
from os import environ
from pathlib import Path
from subprocess import CalledProcessError, CompletedProcess, run
from typing import Self

from yaralyzer.util.constants import INKSCAPE
from yaralyzer.util.helpers.env_helper import is_env_var_set_and_not_false
from yaralyzer.util.helpers.file_helper import load_file, relative_path
from yaralyzer.util.helpers.string_helper import strip_ansi_colors
from yaralyzer.util.logging import log, log_bigly, invocation_str, shell_command_log_str

PYTEST_REBUILD_FIXTURES_ENV_VAR = 'PYTEST_REBUILD_FIXTURES'
WROTE_TO_FILE_REGEX = re.compile(r"Wrote '(.*)' in [\d.]+ seconds")


@dataclass
class ShellResult:
    """
    Wrapper around `CompletedProcess` to help with some common tasks like stripping ansi color codes.
    Also used by pytest to compare output of commands to prerecorded fixture data.

    Attributes:
        result (CompletedProcess): Object returned by `subprocess.run()`
        no_log_args (list[str], optional): Arguments that we would prefer not to see in the logs.
    """
    result: CompletedProcess
    no_log_args: list[str] = field(default_factory=list)

    @property
    def invocation_str(self) -> str:
        """Simplified version of the command that was run."""
        return invocation_str([arg for arg in self.result.args if arg not in (self.no_log_args)])

    @property
    def stderr(self) -> str:
        return self.result.stderr.decode() if isinstance(self.result.stderr, bytes) else self.result.stderr

    @property
    def stderr_stripped(self) -> str:
        return strip_ansi_colors(self.stderr)

    @property
    def stdout(self) -> str:
        return self.result.stdout.decode() if isinstance(self.result.stdout, bytes) else self.result.stdout

    @property
    def stdout_stripped(self) -> str:
        return strip_ansi_colors(self.stdout)

    @classmethod
    def from_cmd(cls, cmd: str | list, verify_success: bool = False, no_log_args: list[str] | None = None) -> Self:
        """
        Alternate constructor that runs `cmd` and gets the result.

        Args:
            cmd (str | list): The shell command to run.
            verify_success (bool, optional): If True run `check_returncode()` (raises on non-zero return codes).
            no_log_args (list[str], optional): Args that might be in `cmd` to not show in logs.
        """
        result = cls(run(safe_args(cmd), capture_output=True, env=environ, text=True), no_log_args or [])

        if verify_success:
            try:
                result.result.check_returncode()
            except (CalledProcessError, FileNotFoundError) as e:
                log_bigly(f"Shell command returned error code! ({e})", result.output_logs(), logging.ERROR)
                raise e

        return result

    def compare_exported_file_to_existing(self, against_dir: Path) -> None:
        """
        Compare the file exported by this command to an existing file in `against_dir`
        This command should have written to the same filename just in a different dir.

        Args:
            against_dir (Path): Dir where the file to compare against exists already.
        """
        new_file_path = self.written_file_path()
        assert new_file_path.exists(), f"'{new_file_path}' does not exist, {self.output_logs()}"
        fixture_path = relative_path(against_dir.joinpath(new_file_path.name))

        if _should_rebuild_fixtures():
            log.warning(f"\nOverwriting fixture '{fixture_path}'\n   with contents of '{new_file_path}'")
            shutil.move(new_file_path, fixture_path)
            return

        assert fixture_path.exists()
        fixture_data = load_file(fixture_path)
        new_data = load_file(new_file_path)
        assert new_data == fixture_data

    def output_logs(self) -> str:
        return shell_command_log_str(self.result, ignore_args=self.no_log_args)

    def written_file_path(self) -> Path:
        """Returns the last match."""
        return self.written_file_paths(self.stderr)[-1]

    def written_file_paths(self, log_text: str) -> list[Path]:
        """Finds the last match."""
        written_paths = [relative_path(Path(m.group(1))) for m in WROTE_TO_FILE_REGEX.finditer(self.stderr_stripped)]
        assert len(written_paths) > 0, f"Could not find 'wrote to file' msg in stderr:\n\n{log_text}"
        log.error(f"Found {len(written_paths)} written files in the logs")
        log.error(self.output_logs())
        return written_paths

    @classmethod
    def run_and_compare_exported_file_to_existing(
        cls,
        cmd: list[str] | str,
        against_dir: Path,
        no_log_args: list[str] | None = None,
    ) -> None:
        """
        Used by pytest to compare fixture data to output of export commands.
        It's here so that pdfalyzer can also use it.

        Args:
            cmd (list[str]): Shell command to run.
            against_dir (Path): Dir where the existing file fixture lives.
            ignorable_args (list[str], optional): Don't log these args if they exist in `cmd`.
        """
        cls.from_cmd(cmd, True, no_log_args).compare_exported_file_to_existing(against_dir)


def get_inkscape_version() -> str | None:
    """Check to see if Inkscape is installed on the current sytem and if so find its version number."""
    try:
        result = ShellResult.from_cmd([INKSCAPE, '--version'], verify_success=True)
        return result.stdout.lower().removeprefix(INKSCAPE).split()[0] or '(unknown)'
    except (CalledProcessError, FileNotFoundError):
        pass


def safe_args(cmd: str | list) -> list[str]:
    """Make sure everything is a string and not, for instance, a `Path`."""
    args = cmd.split() if isinstance(cmd, str) else cmd
    return [str(arg) for arg in args]


def _should_rebuild_fixtures() -> bool:
    """
    True if pytest should overwrite fixture data with new output instead of comparing.
    It's here so that pdfalyzer can also use it.
    """
    return is_env_var_set_and_not_false(PYTEST_REBUILD_FIXTURES_ENV_VAR)
