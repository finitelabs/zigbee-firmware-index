"""Finding the Zigbee OTA image inside a downloaded file."""

from dataclasses import dataclass

from zigpy.ota.image import OTAImageHeader

MAGIC = OTAImageHeader.OTA_HEADER
MIN_HEADER_LENGTH = 56


@dataclass(frozen=True)
class Image:
    start: int
    end: int
    manufacturer: int
    image_type: int
    version: int
    header_string: str


def find(data: bytes) -> Image:
    """The first OTA image in data whose header fits, from the upgrade file identifier through
    the header's total image size. Bytes before it (a vendor wrapper) and after it (a CRC or a
    signature no hub sends) are not part of it."""
    start = data.find(MAGIC)
    while start >= 0:
        try:
            header, _ = OTAImageHeader.deserialize(data[start:])
        except ValueError:
            header = None
        if (
            header is not None
            and header.header_length >= MIN_HEADER_LENGTH
            and header.image_size >= header.header_length
            and start + header.image_size <= len(data)
        ):
            return Image(
                start=start,
                end=start + header.image_size,
                manufacturer=header.manufacturer_id,
                image_type=header.image_type,
                version=header.file_version,
                header_string=bytes(header.header_string)
                .split(b"\x00", 1)[0]
                .decode("ascii", "replace")
                .strip(),
            )
        start = data.find(MAGIC, start + 1)
    raise ValueError("it has no OTA header")
