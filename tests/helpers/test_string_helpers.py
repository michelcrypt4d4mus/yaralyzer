from os.path import basename

from yaralyzer.helpers.string_helper import comma_join, hex_to_string

HEX_STRING = '0D 0A 25 25 45 4F 46 0D 0A'
HEX_STRING_DECODED = '\r\n%%EOF\r\n'


def test_str_join():
    assert comma_join(['a', 'b', 'c']) == 'a, b, c'
    assert comma_join([1, 2, 3]) == '1, 2, 3'
    assert comma_join(['/path/a', '/path/b', 'path/c'], func=basename) == 'a, b, c'


def test_hex_to_string():
    assert hex_to_string(HEX_STRING) == HEX_STRING_DECODED
    assert hex_to_string(HEX_STRING.replace(' ', '')) == HEX_STRING_DECODED
