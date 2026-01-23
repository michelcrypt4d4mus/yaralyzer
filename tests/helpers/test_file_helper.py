from os.path import dirname, join

from yaralyzer.util.helpers.file_helper import files_in_dir


def test_files_in_dir():
    this_dir = dirname(__file__)
    this_dir_files = files_in_dir(this_dir)
    this_dir_files_strs = [str(f) for f in this_dir_files]
    assert len(this_dir_files) >= 3
    assert __file__ in this_dir_files_strs
    assert join(this_dir, 'test_rich_helper.py') in this_dir_files_strs
    assert len(files_in_dir(this_dir, with_extname='illmatic')) == 0
    assert len(files_in_dir(this_dir, with_extname='py')) >= 3
    assert len(files_in_dir(this_dir, with_extname='.py')) >= 3
