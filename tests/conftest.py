from os import environ
from pathlib import Path

import pytest

PYTESTS_DIR = Path(__file__).parent
TMP_DIR = PYTESTS_DIR.joinpath('tmp')
PROJECT_DIR = PYTESTS_DIR.parent
LOG_DIR = PROJECT_DIR.joinpath('log').resolve()

for test_dir in [LOG_DIR, TMP_DIR]:
    if not test_dir.exists():
        print(f"Creating required dir '{LOG_DIR}'")
        test_dir.mkdir(parents=True, exist_ok=True)

# Must be set before importing yaralyzer.helper.env_helper
environ['INVOKED_BY_PYTEST'] = 'True'
environ['YARALYZER_LOG_DIR'] = str(LOG_DIR)

# from yaralyzer.util.helpers.env_helper import is_env_var_set_and_not_false     # noqa: E402
from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.constants import NO_TIMESTAMPS_OPTION, YARALYZE
from yaralyzer.util.helpers.env_helper import temporary_argv
from yaralyzer.util.helpers.file_helper import files_in_dir, load_binary_data  # noqa: E402
from yaralyzer.util.helpers.shell_helper import safe_args
from yaralyzer.yaralyzer import Yaralyzer                                 # noqa: E402

# Dirs
FIXTURES_DIR = PYTESTS_DIR.joinpath('fixtures')
YARA_FIXTURES_DIR = FIXTURES_DIR.joinpath('yara_rules')
RENDERED_FIXTURES_DIR = FIXTURES_DIR.joinpath('rendered')
# Strings
MAXDECODE_SUFFIX = '__maxdecode256'


# Full paths to file fixtures
@pytest.fixture(scope='session')
def il_tulipano_path() -> Path:
    return FIXTURES_DIR.joinpath('il_tulipano_nero.txt')


@pytest.fixture(scope='session')
def tulips_yara_path() -> Path:
    return YARA_FIXTURES_DIR.joinpath('tulips.yara')


@pytest.fixture(scope='session')
def binary_file_path() -> Path:
    return FIXTURES_DIR.joinpath('random_bytes.bin')


@pytest.fixture(scope='session')
def binary_file_bytes(binary_file_path) -> bytes:
    return load_binary_data(binary_file_path)


@pytest.fixture(scope='session')
def tulips_yara_pattern() -> str:
    """The regex that appears in the tulips_yara_path() fixture"""
    return 'tulip.{1,2500}tulip'


# A Yaralyzer
@pytest.fixture
def tulip_base_args(il_tulipano_path, tulips_yara_path) -> list[str]:
    return safe_args([YARALYZE, il_tulipano_path, NO_TIMESTAMPS_OPTION, '-Y', tulips_yara_path])


# A Yaralyzer
@pytest.fixture
def a_yaralyzer(il_tulipano_path, tulip_base_args, tulips_yara_path) -> Yaralyzer:
    with temporary_argv(tulip_base_args):
        YaralyzerConfig.parse_args()
        return Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path)


@pytest.fixture
def tmp_dir() -> Path:
    """Clear the tmp dir when fixture is loaded"""
    for tmp_file in files_in_dir(TMP_DIR):
        tmp_file.unlink()

    return TMP_DIR


@pytest.fixture
def output_dir_args(tmp_dir) -> list[str]:
    return safe_args(['--output-dir', tmp_dir])
