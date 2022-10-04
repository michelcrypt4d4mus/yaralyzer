from os.path import basename

from yaralyzer.helpers.string_helper import comma_join


def test_str_join():
    assert comma_join(['a', 'b', 'c']) == 'a, b, c'
    assert comma_join([1, 2, 3]) == '1, 2, 3'
    assert comma_join(['/path/a', '/path/b', 'path/c'], func=basename) == 'a, b, c'
