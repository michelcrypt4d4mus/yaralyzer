# https://shay-palachy.medium.com/temp-environment-variables-for-pytest-7253230bd777
import sys
from contextlib import contextmanager
from os import environ

import pytest

from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.argument_parser import parser, parse_arguments

ENV_VARS_TO_SUSPEND = []
BASE_ARGV = ['pdfalyze', 'a.pdf', '-Y', 'rules.yara']


#@pytest.fixture(scope='session')
@contextmanager
def setup_and_tear_down_env_vars(env_vars: dict):
    # Will be executed before the first test
    old_environ = dict(environ)
    environ.update(env_vars)
    print(f"Setting up {env_vars}")

    for env_var in ENV_VARS_TO_SUSPEND:
        environ.pop(env_var, default=None)

    yield 'butt'

    # Will be executed after the last test
    environ.clear()
    environ.update(old_environ)


def test_env_var_args():
    with setup_and_tear_down_env_vars({'YARALYZER_SUPPRESS_DECODES_TABLE': 'True'}) as x:
        sys.argv = BASE_ARGV
        parse_arguments()
        print("ENVIRONOL")
        print(environ)
        assert YaralyzerConfig.args.min_chardet_bytes == 9
        assert YaralyzerConfig.args.suppress_decodes_table == True
