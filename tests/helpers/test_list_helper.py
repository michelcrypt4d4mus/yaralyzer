from yaralyzer.helpers.list_helper import flatten


def test_flatten():
    assert flatten([1, 2, 3]) == [1, 2, 3]
    assert flatten([1, 2, [3, 4], [5, [6, 7]]]) == [1, 2, 3, 4, 5, 6, 7]
