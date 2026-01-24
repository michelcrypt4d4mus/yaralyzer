from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.constants import YARALYZE
from yaralyzer.util.helpers.env_helper import temporary_argv, temporary_env

BASE_ARGV = [YARALYZE, __file__, '-Y', 'rules.yara']
ENV_VARS = {'YARALYZER_SURROUNDING_BYTES': '202', 'YARALYZER_SUPPRESS_DECODES_TABLE': 'True'}


def test_env_var_merge():
    with temporary_env(ENV_VARS):
        with temporary_argv(BASE_ARGV):
            parse_arguments()
            assert YaralyzerConfig.args.min_chardet_bytes == 9
            assert YaralyzerConfig.args.suppress_decodes_table is True
            assert YaralyzerConfig.args.surrounding_bytes == 202

        # Ensure CLI overrides env vars
        with temporary_argv(BASE_ARGV + ['--surrounding-bytes', '123']):
            parse_arguments()
            assert YaralyzerConfig.args.surrounding_bytes == 123


def test_private_args():
    with temporary_argv(BASE_ARGV):
        args = parse_arguments()
        assert len(YaralyzerConfig.args._invoked_at_str) == 19
        assert args._standalone_mode is True
        assert args._any_export_selected is False

    with temporary_argv(BASE_ARGV + ['-txt']):
        args = parse_arguments()
        assert args._any_export_selected is True
