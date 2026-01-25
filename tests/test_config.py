from pathlib import Path
from subprocess import run

import pytest

from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.constants import ENV_VARS_OPTION, YARALYZE, YARALYZER_UPPER
from yaralyzer.util.exceptions import InvalidArgumentError
from yaralyzer.util.helpers.env_helper import temporary_env
from yaralyzer.util.helpers.string_helper import strip_ansi_colors


def test_get_env_value(tmp_dir, tulips_yara_path):
    with temporary_env({f"{YARALYZER_UPPER}_OUTPUT_DIR": str(tmp_dir)}):
        assert YaralyzerConfig.get_env_value('OUTPUT_DIR', Path) == tmp_dir
        assert YaralyzerConfig.get_env_value('OUTPUT_DIR') == tmp_dir
        assert YaralyzerConfig.get_env_value('output_dir') == tmp_dir

    with temporary_env({f"{YARALYZER_UPPER}_INT": '5', f"{YARALYZER_UPPER}_FLOAT": '5.5'}):
        assert YaralyzerConfig.get_env_value('INT') == 5
        assert YaralyzerConfig.get_env_value('int', int) == 5

        assert YaralyzerConfig.get_env_value('FLOAT') == 5.5
        assert YaralyzerConfig.get_env_value('float', float) == 5.5

    with temporary_env({f"{YARALYZER_UPPER}_YARA_RULES_DIRS": f'{__file__},{tulips_yara_path}'}):
        assert len(YaralyzerConfig.get_env_value('yara_rules_dirs')) == 2 #['1.yara', '2.yara']

    with temporary_env({f"{YARALYZER_UPPER}_SOME_DIR": '1.yara,2.yara'}):
        with pytest.raises(EnvironmentError):
            YaralyzerConfig.get_env_value('SOME_DIR')


def test_show_configurable_env_vars():
    result = run([YARALYZE, ENV_VARS_OPTION], capture_output=True)
    stderr = strip_ansi_colors(result.stderr.decode())
    assert 'sets --yara-file (comma separated for multiple)' in stderr
