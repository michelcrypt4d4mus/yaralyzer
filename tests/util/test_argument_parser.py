import re

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.theme import CLI_OPTION_TYPE_STYLES
from yaralyzer.util import cli_option_validators
from yaralyzer.util.constants import ENV_VARS_OPTION, YARALYZER
from yaralyzer.util.helpers.env_helper import temporary_argv, temporary_env
from yaralyzer.util.logging import log

ENV_VARS = {
    'YARALYZER_SUPPRESS_DECODES_TABLE': 'True',
    'YARALYZER_SURROUNDING_BYTES': '202',
}


def test_env_var_merge(yaralyze_tulips_cmd):
    with temporary_env(ENV_VARS):
        with temporary_argv(yaralyze_tulips_cmd):
            args = YaralyzerConfig.parse_args()
            assert args == YaralyzerConfig.args
            assert YaralyzerConfig.args.min_chardet_bytes == 9
            assert YaralyzerConfig.args.suppress_decodes_table is True
            assert YaralyzerConfig.args.surrounding_bytes == 202

        # Ensure CLI overrides env vars
        with temporary_argv(yaralyze_tulips_cmd + ['--surrounding-bytes', '123']):
            YaralyzerConfig.parse_args()
            assert YaralyzerConfig.args.surrounding_bytes == 123


def test_option_validators():
    assert cli_option_validators.YaraRegexValidator()('/foo/') == 'foo'


def test_output_dir(output_dir_args, tmp_dir, yaralyze_tulips_cmd):
    with temporary_argv(yaralyze_tulips_cmd + output_dir_args):
        args = YaralyzerConfig.parse_args()
        assert args.output_dir == tmp_dir


def test_private_args(yaralyze_tulips_cmd):
    with temporary_argv(yaralyze_tulips_cmd):
        args = YaralyzerConfig.parse_args()
        assert len(YaralyzerConfig.args._invoked_at_str) == 19
        assert args._any_export_selected is False

    with temporary_argv(yaralyze_tulips_cmd + ['-txt']):
        args = YaralyzerConfig.parse_args()
        assert args._any_export_selected is True

    with temporary_argv(yaralyze_tulips_cmd + ['-png']):
        args = YaralyzerConfig.parse_args()
        assert args.export_svg == 'svg'
        assert args._keep_exported_svg is False


def test_yaralyzer_show_colors_option(yaralyze_run):
    result = yaralyze_run('--show-colors')
    assert 'bytes.decoded' in result.stdout_stripped
    assert YARALYZER in result.stdout_stripped.lower()
    assert 7 < len(result.stdout_lines) < 15


def test_show_configurable_env_vars_option(yaralyze_run):
    result = yaralyze_run(ENV_VARS_OPTION)
    assert 'YARALYZER_SURROUNDING_BYTES' in result.stderr_stripped
    assert '.yaralyzer' in result.stderr_stripped
    assert re.search(r"--yara-file.*comma", result.stderr_stripped)
    lines = result.stderr_stripped.split('\n')
    assert len(lines) > 10
    suffix_line = next(line for line in lines if 'FILE_SUFFIX' in line)
    assert ' str ' in suffix_line

    validator_types = [
        v for v in vars(cli_option_validators).values()
        if isinstance(v, type) and issubclass(v, cli_option_validators.OptionValidator)
            and not v == cli_option_validators.OptionValidator  # noqa: E131
    ]

    for validator in validator_types:
        assert validator().arg_type_str() in CLI_OPTION_TYPE_STYLES
