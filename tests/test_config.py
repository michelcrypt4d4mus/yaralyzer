from os import environ
from pathlib import Path

from yaralyzer.config import YaralyzerConfig
from yaralyzer.util.constants import YARALYZER_UPPER
from yaralyzer.util.helpers.env_helper import temporary_env


def test_get_env_value(tmp_dir):
    with temporary_env({f"{YARALYZER_UPPER}_OUTPUT_DIR": str(tmp_dir)}):
        assert YaralyzerConfig.get_env_value('OUTPUT_DIR', Path) == tmp_dir
        assert YaralyzerConfig.get_env_value('OUTPUT_DIR') == tmp_dir
        assert YaralyzerConfig.get_env_value('output_dir') == tmp_dir

    with temporary_env({f"{YARALYZER_UPPER}_INT": '5', f"{YARALYZER_UPPER}_FLOAT": '5.5'}):
        assert YaralyzerConfig.get_env_value('INT') == 5
        assert YaralyzerConfig.get_env_value('int', int) == 5

        assert YaralyzerConfig.get_env_value('FLOAT') == 5.5
        assert YaralyzerConfig.get_env_value('float', float) == 5.5
