import pytest

from yaralyzer.config import YaralyzerConfig
from yaralyzer.output.theme import CLI_OPTION_TYPE_STYLES
from yaralyzer.util import cli_option_validators
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.constants import ENV_VARS_OPTION, YARALYZE
from yaralyzer.util.helpers.env_helper import temporary_argv, temporary_env
from yaralyzer.util.helpers.shell_helper import ShellResult, safe_args
from yaralyzer.util.logging import log, log_console

ENV_VARS = {
    'YARALYZER_SUPPRESS_DECODES_TABLE': 'True',
    'YARALYZER_SURROUNDING_BYTES': '202',
}


@pytest.fixture
def valid_argv(tulips_yara_path) -> list[str]:
    return safe_args([YARALYZE, __file__, '-Y', tulips_yara_path])


def test_env_var_merge(valid_argv):
    with temporary_env(ENV_VARS):
        with temporary_argv(valid_argv):
            args = parse_arguments()
            assert args == YaralyzerConfig.args
            assert YaralyzerConfig.args.min_chardet_bytes == 9
            assert YaralyzerConfig.args.suppress_decodes_table is True
            assert YaralyzerConfig.args.surrounding_bytes == 202

        # Ensure CLI overrides env vars
        with temporary_argv(valid_argv + ['--surrounding-bytes', '123']):
            parse_arguments()
            assert YaralyzerConfig.args.surrounding_bytes == 123


def test_option_validators():
    assert cli_option_validators.YaraRegexValidator()('/foo/') == 'foo'


def test_output_dir(valid_argv, output_dir_args, tmp_dir):
    with temporary_argv(valid_argv + output_dir_args):
        args = parse_arguments()
        assert args.output_dir == tmp_dir


def test_private_args(valid_argv):
    with temporary_argv(valid_argv):
        args = parse_arguments()
        assert len(YaralyzerConfig.args._invoked_at_str) == 19
        assert args._standalone_mode is True
        assert args._any_export_selected is False

    with temporary_argv(valid_argv + ['-txt']):
        args = parse_arguments()
        assert args._any_export_selected is True

    with temporary_argv(valid_argv + ['-png']):
        args = parse_arguments()
        assert args.export_svg == 'svg'
        assert args._keep_exported_svg is False


def test_show_configurable_env_vars_option():
    result = ShellResult.from_cmd([YARALYZE, ENV_VARS_OPTION], verify_success=True)
    assert 'YARALYZER_SURROUNDING_BYTES' in result.stderr_stripped
    assert '.yaralyzer' in result.stderr_stripped
    assert 'sets --yara-file (comma separated for multiple)' in result.stderr_stripped
    lines = result.stderr_stripped.split('\n')
    assert len(lines) > 10
    suffix_line = next(line for line in lines if 'FILE_SUFFIX' in line)
    assert ' str ' in suffix_line

    validator_types = [
        v for v in vars(cli_option_validators).values()
        if isinstance(v, type) and issubclass(v, cli_option_validators.OptionValidator) \
            and not v == cli_option_validators.OptionValidator
    ]

    for validator in validator_types:
        assert validator().arg_type_str() in CLI_OPTION_TYPE_STYLES
