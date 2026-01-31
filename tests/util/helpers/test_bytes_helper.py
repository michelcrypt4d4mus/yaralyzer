import pytest

from yaralyzer.encoding_detection.character_encodings import UTF_8, UTF_16, UTF_32, ISO_8859_1
from yaralyzer.output.file_hashes_table import BytesInfo
from yaralyzer.util.helpers.bytes_helper import clean_byte_string, truncate_for_encoding
from yaralyzer.util.helpers.env_helper import is_windows

LONG_BYTES = b"\x04f\xff\xa1\x04f\xff\xa1\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\x00\x0b\x04f\x00\xb3\x04f\x00)\x04f\x00]\x04f\xff\xb8\x04f\x00A\x04f\x00\xa0\x04f\x00\r\x04f\x00d\x04f\xff\xeb\x04f\x00\x9a\x04f\xff\xe9\x04f\x00u\x04f\x00G\x04f\x01u\x04f\x01>\x04f\x01t\x04f\x028\x04f\x02\x8c\x04f\x02'\x04f\x02|\x04f\x01\x15\x04f\x01C\x04f\x00G\x04f\x00\r\x04f\xff\xf4\x04f\x00\x00\x04f\x008\x04f\xff\xee\x04f\xff\x9e\x04f\xff\xee\x04f\xff\x93\x04f\xff\xee\x04f\xff\xd4\x04f\x00m\x04f\x00\xa1\x04f\x00,\x04f\x00=\x04f\x008\x04f\x008\x04f\x00"  # noqa: E501
TRUNCATE_TEST_BYTES = b"1234567"

LINUX_HASHES = {
    'md5': '9F484F190D5AFEC09D2070F68AF8921B',
    'sha1': 'A30499F981B1757E62CF24CF656038F992DA6077',
    'sha256': 'A870D7D50244AB0A169AF27A325F5895FBEA95371E8D972BE293462C41570BC3',
}


def test_clean_byte_string():
    assert clean_byte_string(b'\xbbJS') == '\\xbbJS'
    cleaned_bytes = clean_byte_string(LONG_BYTES)
    assert cleaned_bytes[0:4] == '\\x04'
    assert "\\'" not in cleaned_bytes


@pytest.mark.skipif(is_windows(), reason="hashes are different on windows?")
def test_compute_file_hashes(il_tulipano_path):
    bytes_info = BytesInfo.for_file(il_tulipano_path)
    assert bytes_info.size == 350 if is_windows() else 333
    assert bytes_info.hash_dict() == LINUX_HASHES


def test_truncate_for_encoding():
    assert truncate_for_encoding(TRUNCATE_TEST_BYTES, UTF_8) == TRUNCATE_TEST_BYTES
    assert truncate_for_encoding(TRUNCATE_TEST_BYTES, UTF_16) == b'123456'
    assert truncate_for_encoding(TRUNCATE_TEST_BYTES, UTF_32) == b'1234'
    assert truncate_for_encoding(b'abcdefghijklmnopqrstuvwx', UTF_32) == b'abcdefghijklmnopqrstuvwx'
    assert truncate_for_encoding(b'123', UTF_32) == b'123'  # Too short
    assert truncate_for_encoding(TRUNCATE_TEST_BYTES, ISO_8859_1) == TRUNCATE_TEST_BYTES
