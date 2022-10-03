from os import environ, path
import pytest

environ['INVOKED_BY_PYTEST'] = 'True'

from yaralyzer.yaralyzer import Yaralyzer
FILE_FIXTURE_PATH = path.join(path.dirname(__file__), 'file_fixtures')


# Full paths to PDF test fixtures
@pytest.fixture(scope='session')
def il_tulipano_path():
    return path.join(FILE_FIXTURE_PATH, 'il_tulipano_nero.txt')

@pytest.fixture(scope='session')
def tulips_yara_path():
    return path.join(FILE_FIXTURE_PATH, 'tulips.yara')


# A Yaralyzer
@pytest.fixture(scope="session")
def yaralyzer(il_tulipano_path, tulips_yara_path):
    return Yaralyzer.for_rules_files(il_tulipano_path, [tulips_yara_path])
