# https://shay-palachy.medium.com/temp-environment-variables-for-pytest-7253230bd777
import sys
from contextlib import contextmanager
from os import environ

from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.argument_parser import parse_arguments

ENV_VARS_TO_SUSPEND = []
BASE_ARGV = ['pdfalyze', 'a.pdf', '-Y', 'rules.yara']


@contextmanager
def setup_and_tear_down_env_vars(env_vars: dict):
    # Will be executed before the first test
    old_environ = dict(environ)
    environ.update(env_vars)

    for env_var in ENV_VARS_TO_SUSPEND:
        environ.pop(env_var, default=None)

    yield

    # Will be executed after the last test
    environ.clear()
    environ.update(old_environ)


def test_env_var_bool():
    with setup_and_tear_down_env_vars({'YARALYZER_SUPPRESS_DECODES_TABLE': 'True'}):
        sys.argv = BASE_ARGV
        parse_arguments()
        assert YaralyzerConfig.args.min_chardet_bytes == 9
        assert YaralyzerConfig.args.suppress_decodes_table is True


def test_env_var_int():
    with setup_and_tear_down_env_vars({'YARALYZER_SURROUNDING_BYTES': '202'}):
        sys.argv = BASE_ARGV
        parse_arguments()
        assert YaralyzerConfig.args.surrounding_bytes == 202


def test_cli_overrides_env():
    with setup_and_tear_down_env_vars({'YARALYZER_SURROUNDING_BYTES': '202'}):
        sys.argv = BASE_ARGV + ['--surrounding-bytes', '123']
        parse_arguments()
        assert YaralyzerConfig.args.surrounding_bytes == 123
