from os import environ
from pathlib import Path

import pytest

PYTESTS_DIR = Path(__file__).parent
PROJECT_DIR = PYTESTS_DIR.parent
LOG_DIR = PROJECT_DIR.joinpath('log').resolve()
TMP_DIR = PYTESTS_DIR.joinpath('tmp')

# Some env vars that we need or are helpful for pytest
environ['INVOKED_BY_PYTEST'] = 'True'
environ['YARALYZER_LOG_DIR'] = str(LOG_DIR)

from yaralyzer.helpers.env_helper import is_env_var_set_and_not_false     # noqa: E402
from yaralyzer.helpers.file_helper import files_in_dir, load_binary_data  # noqa: E402
from yaralyzer.yaralyzer import Yaralyzer                                 # noqa: E402

FIXTURES_DIR = PYTESTS_DIR.joinpath('file_fixtures')
YARA_FIXTURES_DIR = FIXTURES_DIR.joinpath('yara_rules')
RENDERED_FIXTURES_DIR = FIXTURES_DIR.joinpath('rendered')
PYTEST_REBUILD_FIXTURES_ENV_VAR = 'PYTEST_REBUILD_FIXTURES'
SHOULD_REBUILD_FIXTURES = is_env_var_set_and_not_false(PYTEST_REBUILD_FIXTURES_ENV_VAR)


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
@pytest.fixture(scope="session")
def a_yaralyzer(il_tulipano_path, tulips_yara_path) -> Yaralyzer:
    return Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path)


@pytest.fixture
def tmp_dir() -> Path:
    """Clear the tmp dir when fixture is loaded"""
    for tmp_file in files_in_dir(TMP_DIR):
        tmp_file.unlink()

    return TMP_DIR
