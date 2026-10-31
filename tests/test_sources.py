import hashlib
import json
import ssl
from pathlib import Path

from conftest import ota_file
from zigpy.ota.providers import LocalOtaImageMetadata, RemoteOtaImageMetadata

from firmware_index import sources

DATA = Path(__file__).parent / "data"


def test_community_entries_keep_every_field_the_format_has():
    body = (DATA / "community-sample.json").read_bytes()
    raw = json.loads(body)
    got = sources.from_index("community", 3, body)
    assert len(got) == len(raw)
    for c, e in zip(got, raw, strict=True):
        assert (c.manufacturer, c.image_type, c.version) == (
            e["manufacturerCode"],
            e["imageType"],
            e["fileVersion"],
        )
        assert c.url == e["url"]
        assert c.checksum == f"sha512:{e['sha512']}"
        assert c.model_id == e.get("modelId")
        assert c.manufacturer_names == e.get("manufacturerName")
        assert c.hardware_min == e.get("hardwareVersionMin")
        assert c.min_file_version == e.get("minFileVersion")
        assert c.release_notes == e.get("releaseNotes")
        assert c.original_url == (e.get("originalUrl") or e["url"])
        assert c.file_name == sources.file_name(
            e["fileName"], c.manufacturer, c.image_type, c.version
        )


def test_a_name_unsafe_in_a_url_is_replaced_by_the_identity():
    assert sources.file_name("https://x.test/a b.ota", 0x1234, 1, 0x20) == "1234-0001-00000020.ota"
    assert sources.file_name("https://x.test/download?id=9", 0x1234, 1, 2).endswith(".ota")
    assert sources.file_name("https://x.test/Vendor/fw_1.2.ota", 1, 1, 1) == "fw_1.2.ota"


def test_zigpy_metadata_makes_one_candidate_per_model(tmp_path):
    path = tmp_path / "fw.ota"
    data = ota_file(0x1234, 1, 0x20)
    path.write_bytes(data)
    meta = LocalOtaImageMetadata(
        path=path,
        file_version=0x20,
        manufacturer_id=0x1234,
        image_type=1,
        checksum=f"sha512:{hashlib.sha512(data).hexdigest()}",
        file_size=len(data),
        model_names=("A", "B"),
        manufacturer_names=("Vendor",),
        min_hardware_version=1,
        release_notes="notes",
    )
    got = sources.from_zigpy("zigpy-ota", 2, [meta])
    assert [c.model_id for c in got] == ["A", "B"]
    assert all(c.manufacturer_names == ["Vendor"] and c.hardware_min == 1 for c in got)
    assert got[0].meta is meta
    assert sources.Candidate.from_json(got[0].to_json()).model_id == "A"


def test_a_candidate_from_a_remote_provider_saves_without_its_ssl_context():
    meta = RemoteOtaImageMetadata(
        url="https://vendor.test/fw.ota",
        file_version=1,
        manufacturer_id=0x1234,
        image_type=1,
        ssl_ctx=ssl.create_default_context(),
    )
    [c] = sources.from_zigpy("ikea", 6, [meta])
    saved = json.loads(json.dumps(c.to_json()))
    assert "meta" not in saved
    assert sources.Candidate.from_json(saved).url == "https://vendor.test/fw.ota"
