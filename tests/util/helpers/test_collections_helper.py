from yaralyzer.util.helpers.collections_helper import flatten, get_dict_key_by_value


def test_flatten():
    assert flatten([1, 2, 3]) == [1, 2, 3]
    assert flatten([1, 2, [3, 4], [5, [6, 7]]]) == [1, 2, 3, 4, 5, 6, 7]


def test_get_dict_key_by_value():
    arr = [1, 2, 3]
    hsh = {'a': 1, 'b': b'BYTES', 1: arr}
    assert get_dict_key_by_value(hsh, 1) == 'a'
    assert get_dict_key_by_value(hsh, b'BYTES') == 'b'
    assert get_dict_key_by_value(hsh, arr) == 1
