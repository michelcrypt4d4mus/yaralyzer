from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.constants import YARALYZE
from yaralyzer.util.helpers.env_helper import temporary_argv, temporary_env

ENV_VARS_TO_SUSPEND = []
BASE_ARGV = [YARALYZE, __file__, '-Y', 'rules.yara']


def test_env_var_bool():
    with temporary_env({'YARALYZER_SUPPRESS_DECODES_TABLE': 'True'}):
        with temporary_argv(BASE_ARGV):
            parse_arguments()
            assert YaralyzerConfig.args.min_chardet_bytes == 9
            assert YaralyzerConfig.args.suppress_decodes_table is True


def test_env_var_int():
    with temporary_env({'YARALYZER_SURROUNDING_BYTES': '202'}):
        with temporary_argv(BASE_ARGV):
            parse_arguments()
            assert YaralyzerConfig.args.surrounding_bytes == 202

def test_cli_overrides_env():
    with temporary_env({'YARALYZER_SURROUNDING_BYTES': '202'}):
        with temporary_argv(BASE_ARGV + ['--surrounding-bytes', '123']):
            parse_arguments()
            assert YaralyzerConfig.args.surrounding_bytes == 123
