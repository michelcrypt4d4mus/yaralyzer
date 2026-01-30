"""
Utility methods for running shell commands, including some code smelly pytest related stuff
that needs to be here because it's used by the pytest suite in this repo and in Pdfalyzzer.
"""
import logging
import re
import shutil
from dataclasses import dataclass, field
from os import environ, getlogin
from pathlib import Path
from subprocess import CalledProcessError, CompletedProcess, run
# from typing import Self  # TODO: this requires python 3.11

from yaralyzer.util.constants import INKSCAPE
from yaralyzer.util.helpers.env_helper import PYTEST_REBUILD_FIXTURES_ENV_VAR, _should_rebuild_fixtures
from yaralyzer.util.helpers.file_helper import load_file, relative_path
from yaralyzer.util.helpers.string_helper import strip_ansi_colors
from yaralyzer.util.logging import LOG_SEPARATOR, invocation_str, log, log_bigly, log_console

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
    def stderr_stripped(self) -> str | None:
        return strip_ansi_colors(self.stderr) if self.stderr is not None else None

    @property
    def stdout(self) -> str:
        return self.result.stdout.decode() if isinstance(self.result.stdout, bytes) else self.result.stdout

    @property
    def stdout_lines(self) -> list[str]:
        return [] if self.stdout_stripped is None else self.stdout_stripped.split('\n')

    @property
    def stdout_stripped(self) -> str | None:
        return strip_ansi_colors(self.stdout) if self.stdout is not None else None

    @classmethod
    def from_cmd(
        cls,
        cmd: str | list,
        verify_success: bool = False,
        no_log_args: list[str] | None = None
    ) -> 'ShellResult':
        """
        Alternate constructor that runs `cmd` and gets the result.

        Args:
            cmd (str | list): The shell command to run.
            verify_success (bool, optional): If True run `check_returncode()` (raises on non-zero return codes).
            no_log_args (list[str], optional): Args that might be in `cmd` to not show in logs.
        """
        result = cls(run(safe_args(cmd), capture_output=True, env=environ, text=True), no_log_args or [])
        log.debug(f"Ran command: {result.invocation_str}")

        if verify_success:
            try:
                result.result.check_returncode()
            except (CalledProcessError, FileNotFoundError) as e:
                log_bigly(f"Shell command returned error code! ({e})", result.output_logs(), logging.ERROR)
                raise e

        return result

    def compare_exported_files_to_existing(self, against_dir: Path, only_last_file: bool = False) -> None:
        """
        Compare the file exported by this command to an existing file in `against_dir`
        This command should have written to the same filename just in a different dir.

        Args:
            against_dir (Path): Dir where the file to compare against exists already.
            only_last_file (bool, optional): If True only compare the last file that was written.
        """
        exported_paths = self.exported_file_paths()[-1:] if only_last_file else self.exported_file_paths()

        for exported_path in exported_paths:
            assert exported_path.exists(), f"'{exported_path}' does not exist, {self.output_logs()}"
            existing_path = relative_path(against_dir.joinpath(exported_path.name))
            exported_data = load_file(exported_path)

            if _should_rebuild_fixtures():
                if getlogin() in strip_ansi_colors(exported_data):
                    raise ValueError(f"Found local username in exported fixture data!")

                log.warning(f"\nOverwriting fixture '{existing_path}'\n   with contents of '{exported_path}'")
                shutil.move(exported_path, existing_path)
                continue

            assert existing_path.exists(), f"Existing file we want to compare against '{existing_path}' doesn't exist!"
            existing_data = load_file(existing_path)
            assert exported_data == existing_data, self._fixture_mismatch_log_msg(existing_path, exported_path)
            log.debug(f"Validated '{exported_path}' as matching the exiting file...")

    def exported_file_paths(self) -> list[Path]:
        """Finds the last match."""
        written_paths = [
            relative_path(Path(m.group(1)))
            for m in WROTE_TO_FILE_REGEX.finditer(self.stderr_stripped or '')
        ]

        assert len(written_paths) > 0, f"Could not find 'wrote to file' msg in stderr:\n\n{self.stderr}"
        log_bigly(f"Found {len(written_paths)} written files in the logs", self.output_logs())
        return written_paths

    def last_exported_file_path(self) -> Path:
        """Returns the last file that exported by this shell command."""
        return self.exported_file_paths()[-1]

    def output_logs(self, with_streams: bool = False) -> str:
        """Long string with all info about a shell command's execution and output."""
        cmd = invocation_str([arg for arg in self.result.args if arg not in (self.no_log_args or [])])
        msg = f"Return code {self.result.returncode} from shell command:\n\n{cmd}"

        if True or with_streams:
            for i, stream in enumerate([self.stdout, self.stderr]):
                label = 'stdout' if i == 0 else 'stderr'
                msg += f"\n\n[{label}"

                if stream:
                    msg += f"]\n{LOG_SEPARATOR}\n{stream}\n{LOG_SEPARATOR}"
                else:
                    msg += f" (empty)]"

        return msg + "\n"

    def _fixture_mismatch_log_msg(self, existing_path: Path, export_path: Path) -> str:
        """Sometimes pytest's diff is very, very slow, so we handle showing our own diff."""
        error_msg = f"Contents of '{export_path}' does not match fixture: '{existing_path}'\n\n" \
                    f'{self.invocation_str}\n\n' \
                    f"Fixtures can be updated by running '{PYTEST_REBUILD_FIXTURES_ENV_VAR}=True pytest'\n\n" \

        try:
            diff_result = type(self).from_cmd(['diff', '-a', existing_path, export_path])
            print(f"{error_msg}Result of diff '{existing_path}'\n       against '{export_path}'\n")
            print(diff_result.output_logs(True))
            print(f"\n\n[stderr]\n{self.stderr}\n\n")
        except Exception:
            log_console.print(
                f"Failed to print diff of '{existing_path}'\n        against '{export_path}'!", style='bright_red bold'
            )

        return error_msg

    @classmethod
    def run_and_compare_exported_files_to_existing(
        cls,
        cmd: list[str] | str,
        against_dir: Path,
        no_log_args: list[str] | None = None,
    ) -> 'ShellResult':
        """
        Used by pytest to compare fixture data to output of export commands. Here so that pdfalyzer can use it.

        Args:
            cmd (list[str] | str): Shell command to run.
            against_dir (Path): Dir where the existing files you want to compare the new oones to live.
            ignorable_args (list[str], optional): Don't log these args if they exist in `cmd`.
        """
        shell_result = cls.from_cmd(cmd, True, no_log_args)
        shell_result.compare_exported_files_to_existing(against_dir)
        return shell_result


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
