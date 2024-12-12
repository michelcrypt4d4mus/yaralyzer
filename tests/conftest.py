from os import environ, pardir, path, remove
from pathlib import Path

import pytest

PYTESTS_DIR = path.dirname(__file__)
LOG_DIR = str(Path(path.join(PYTESTS_DIR, pardir, 'log')).resolve())
FILE_FIXTURE_PATH = path.join(PYTESTS_DIR, 'file_fixtures')

# Some env vars that we need or are helpful for pytest
environ['INVOKED_BY_PYTEST'] = 'True'
environ['YARALYZER_LOG_DIR'] = LOG_DIR

from yaralyzer.helpers.file_helper import files_in_dir, load_binary_data
from yaralyzer.yaralyzer import Yaralyzer


# Full paths to file fixtures
@pytest.fixture(scope='session')
def il_tulipano_path():
    return path.join(FILE_FIXTURE_PATH, 'il_tulipano_nero.txt')


@pytest.fixture(scope='session')
def tulips_yara_path():
    return path.join(FILE_FIXTURE_PATH, 'yara_rules', 'tulips.yara')


@pytest.fixture(scope='session')
def binary_file_path():
    return path.join(FILE_FIXTURE_PATH, 'random_bytes.bin')


@pytest.fixture(scope='session')
def binary_file_bytes(binary_file_path):
    return load_binary_data(binary_file_path)


@pytest.fixture(scope='session')
def tulips_yara_regex():
    """The regex that appears in the tulips_yara_path() fixture"""
    return 'tulip.{1,2500}tulip'


# A Yaralyzer
@pytest.fixture(scope="session")
def a_yaralyzer(il_tulipano_path, tulips_yara_path):
    return Yaralyzer.for_rules_files([tulips_yara_path], il_tulipano_path)


@pytest.fixture
def tmp_dir():
    """Clear the tmp dir when fixture is loaded"""
    tmpdir = path.join(path.dirname(__file__), 'tmp')

    for file in files_in_dir(tmpdir):
        remove(file)

    return tmpdir
