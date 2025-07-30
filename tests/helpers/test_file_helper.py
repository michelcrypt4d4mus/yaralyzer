from os.path import dirname

from yaralyzer.helpers.file_helper import files_in_dir


def test_files_in_dir():
    this_dir_files = files_in_dir(dirname(__file__))
    assert len(this_dir_files) >= 3
    assert __file__ in this_dir_files
    assert len(files_in_dir(dirname(__file__), with_extname='illmatic')) == 0
    assert len(files_in_dir(dirname(__file__), with_extname='py')) >= 3
