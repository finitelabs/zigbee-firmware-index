import pytest
from conftest import ota_file

from firmware_index import ota


def test_a_plain_file_is_its_own_image():
    data = ota_file(0x1234, 0x0001, 0x20)
    img = ota.find(data)
    assert (img.start, img.end) == (0, len(data))
    assert (img.manufacturer, img.image_type, img.version) == (0x1234, 0x0001, 0x20)
    assert img.header_string == "Test image"


def test_a_wrapper_and_trailing_bytes_are_cut_off():
    core = ota_file(0x1234, 0x0001, 0x20)
    data = ota_file(0x1234, 0x0001, 0x20, prefix=b"NGIS" + bytes(36), suffix=b"\xaa" * 17)
    img = ota.find(data)
    assert data[img.start : img.end] == core


def test_an_identifier_in_a_wrapper_that_is_no_header_is_skipped():
    core = ota_file(0x1234, 0x0001, 0x20)
    data = b"\x1e\xf1\xee\x0b" + bytes(8) + core
    img = ota.find(data)
    assert data[img.start : img.end] == core


def test_a_file_without_a_header_is_refused():
    with pytest.raises(ValueError, match="no OTA header"):
        ota.find(b"not firmware" * 20)


def test_a_header_whose_size_overruns_the_file_is_refused():
    with pytest.raises(ValueError, match="no OTA header"):
        ota.find(ota_file(0x1234, 0x0001, 0x20)[:-10])
