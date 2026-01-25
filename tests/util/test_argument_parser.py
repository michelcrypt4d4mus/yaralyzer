import pytest

from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.argument_parser import parse_arguments
from yaralyzer.util.cli_options import cli_option_validators
from yaralyzer.util.cli_options.option_validator import OptionValidator
from yaralyzer.util.constants import ENV_VARS_OPTION, YARALYZE
from yaralyzer.util.helpers.env_helper import temporary_argv, temporary_env
from yaralyzer.util.helpers.shell_helper import ShellResult, safe_args
from yaralyzer.util.logging import log_console
from yaralyzer.output.theme import CLI_OPTION_TYPE_STYLES

BASE_ARGV = [YARALYZE, __file__, '-Y', 'rules.yara']
ENV_VARS = {'YARALYZER_SURROUNDING_BYTES': '202', 'YARALYZER_SUPPRESS_DECODES_TABLE': 'True'}


@pytest.fixture
def valid_argv(tulips_yara_path) -> list[str]:
    return safe_args([YARALYZE, __file__, '-Y', tulips_yara_path])


def test_env_var_merge(valid_argv):
    with temporary_env(ENV_VARS):
        with temporary_argv(valid_argv):
            parse_arguments()
            assert YaralyzerConfig.args.min_chardet_bytes == 9
            assert YaralyzerConfig.args.suppress_decodes_table is True
            assert YaralyzerConfig.args.surrounding_bytes == 202

        # Ensure CLI overrides env vars
        with temporary_argv(valid_argv + ['--surrounding-bytes', '123']):
            parse_arguments()
            assert YaralyzerConfig.args.surrounding_bytes == 123


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
        assert args._svg_requested is False


def test_env_vars_option():
    result = ShellResult.from_cmd([YARALYZE, ENV_VARS_OPTION], verify_success=True)
    assert 'YARALYZER_SURROUNDING_BYTES' in result.stderr_stripped
    assert '.yaralyzer' in result.stderr_stripped
    assert len(result.stderr_stripped.split('\n')) > 10


def test_option_env_var_styles():
    validator_types = [
        v for v in vars(cli_option_validators).values()
        if isinstance(v, type) and issubclass(v, OptionValidator) and not v == OptionValidator
    ]

    for validator in validator_types:
        assert validator().arg_type_str() in CLI_OPTION_TYPE_STYLES
