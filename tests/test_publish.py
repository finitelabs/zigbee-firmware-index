import asyncio
import hashlib
import json

from conftest import index_entry, ota_file
from zigpy.ota.providers import LocalOtaImageMetadata

from firmware_index import db as dbm
from firmware_index import keys, notify, publish, sources

A = "https://a.test/index.json"
B = "https://b.test/index.json"


def files(world, n, host="a.test", start=0):
    """n files on host, each with its index entry."""
    out = []
    for i in range(start, start + n):
        data = ota_file(0x1000 + i, 1, 0x10)
        url = f"https://{host}/images/fw{i}.ota"
        world.fetcher.serve(url, data)
        out.append(index_entry(url, data, 0x1000 + i, 1, 0x10))
    return out


def test_a_run_publishes_our_copies_a_signed_snapshot_and_the_page(world):
    world.source("community", 3, A)
    core = ota_file(0x1234, 1, 0x20)
    wrapped = ota_file(0x1234, 1, 0x20, prefix=b"NGIS" + bytes(36), suffix=b"\xaa" * 8)
    world.fetcher.serve("https://a.test/images/v.ota", wrapped)
    world.fetcher.serve(
        A, [index_entry("https://a.test/images/v.ota", wrapped, 0x1234, 1, 0x20, modelId="M1")]
    )

    report = world.run()

    assert report.status == publish.OK and report.changed
    [e] = world.index()
    sha = hashlib.sha512(core).hexdigest()
    assert e["sha512"] == sha
    assert e["fileSize"] == len(core)
    assert e["url"] == f"https://ota.example.test/images/{sha[:16]}/v.ota"
    assert e["upstreamSha512"] == hashlib.sha512(wrapped).hexdigest()
    assert e["originalUrl"] == "https://a.test/images/v.ota"
    assert e["sources"] == ["community"]
    assert e["modelId"] == "M1"
    assert e["firstSeen"] == "2026-10-30T04:00:00Z"
    assert world.read(f"images/{sha[:16]}/v.ota") == core

    latest = json.loads(world.read("latest.json"))
    snapshot = world.read(latest["snapshot"])
    assert snapshot == world.read("index.json")
    assert latest["sha512"] == hashlib.sha512(snapshot).hexdigest()
    assert latest["checked"] == "2026-10-30T04:00:00Z"
    message = f"{latest['snapshot']}\n{latest['sha512']}".encode()
    assert keys.verify(world.public, message, latest["signature"])
    assert world.read("signing-key.pub").decode().strip() == world.public
    assert b"1 files in all" in world.read("index.html")


def test_a_run_that_changes_nothing_only_records_when_it_checked(world):
    world.source("community", 3, A)
    world.fetcher.serve(A, files(world, 3))
    world.run()
    first = json.loads(world.read("latest.json"))
    world.clock.advance(days=1)
    world.fetcher.calls.clear()

    report = world.run()

    assert report.status == publish.OK and not report.changed
    latest = json.loads(world.read("latest.json"))
    assert latest["snapshot"] == first["snapshot"]
    assert latest["checked"] == "2026-10-31T04:00:00Z"
    assert world.fetcher.calls == [A]
    assert len(list((world.site / "snapshots").iterdir())) == 1


def test_a_file_that_fails_a_check_is_left_out_with_its_reason(world):
    world.source("community", 3, A)
    good = files(world, 1)
    bad_sum = index_entry("https://a.test/x.ota", ota_file(0x2000, 1, 1), 0x2000, 1, 1)
    world.fetcher.serve("https://a.test/x.ota", ota_file(0x2000, 1, 2))
    other = ota_file(0x3000, 1, 1)
    world.fetcher.serve("https://a.test/y.ota", other)
    wrong_header = index_entry("https://a.test/y.ota", other, 0x3000, 2, 1)
    nothing = b"not firmware" * 10
    world.fetcher.serve("https://a.test/z.ota", nothing)
    no_header = index_entry("https://a.test/z.ota", nothing, 0x4000, 1, 1)
    world.fetcher.serve(A, good + [bad_sum, wrong_header, no_header])

    report = world.run()

    assert [e["manufacturerCode"] for e in world.index()] == [0x1000]
    reasons = sorted(f["reason"] for f in report.failures)
    assert reasons[0].startswith("it has no OTA header")
    assert reasons[1].startswith("its header names 0x3000/0x0001")
    assert reasons[2] == "its sha512 does not match the source's"


def test_a_failing_source_keeps_its_last_list_and_alerts_once(world):
    world.source("community", 3, A)
    world.fetcher.serve(A, files(world, 2))
    world.run()
    del world.fetcher.files[A]

    second = world.run()
    third = world.run()

    assert [s["status"] for s in second.sources] == ["failed"]
    assert len(world.index()) == 2
    assert any("source community failed" in a for a in second.alerts)
    assert not third.alerts
    world.fetcher.serve(A, files(world, 2))
    assert world.run().alerts == ["source community recovered"]


def test_a_source_that_suddenly_lists_nothing_counts_as_failed(world):
    world.source("community", 3, A)
    world.fetcher.serve(A, files(world, 2))
    world.run()
    world.fetcher.serve(A, [])

    report = world.run()

    assert report.sources[0]["error"] == "ValueError: it returned no entries"
    assert len(world.index()) == 2


def test_a_delayed_source_waits_its_days(world):
    world.source("vendor", 4, A, delay_days=7)
    world.fetcher.serve(A, files(world, 1))
    report = world.run()
    assert report.counts["waiting"] == 1 and world.index() == []

    world.clock.advance(days=7)
    assert len(world.index()) == 0
    world.run()
    assert len(world.index()) == 1


def test_a_clash_goes_to_the_higher_priority_and_one_file_names_every_source(world):
    world.source("curated", 2, B)
    world.source("community", 3, A)
    shared = ota_file(0x1234, 1, 0x20)
    ours = ota_file(0x5678, 1, 1)
    theirs = ota_file(0x5678, 1, 1, payload=b"b" * 9)
    world.fetcher.serve("https://a.test/s.ota", shared)
    world.fetcher.serve("https://b.test/s.ota", shared)
    world.fetcher.serve("https://a.test/c.ota", ours)
    world.fetcher.serve("https://b.test/c.ota", theirs)
    world.fetcher.serve(
        A,
        [
            index_entry("https://a.test/s.ota", shared, 0x1234, 1, 0x20),
            index_entry("https://a.test/c.ota", ours, 0x5678, 1, 1),
        ],
    )
    world.fetcher.serve(
        B,
        [
            index_entry("https://b.test/s.ota", shared, 0x1234, 1, 0x20),
            index_entry("https://b.test/c.ota", theirs, 0x5678, 1, 1),
        ],
    )

    report = world.run()

    by_mfr = {e["manufacturerCode"]: e for e in world.index()}
    assert by_mfr[0x1234]["sources"] == ["community", "curated"]
    assert by_mfr[0x5678]["sha512"] == hashlib.sha512(theirs).hexdigest()
    assert by_mfr[0x5678]["sources"] == ["curated"]
    [clash] = report.clashes
    assert clash["kept"].startswith("curated") and clash["over"][0].startswith("community")


def test_the_brake_holds_the_index_unless_told_to_publish_anyway(world):
    world.source("community", 3, A)
    listed = files(world, 20)
    world.fetcher.serve(A, listed)
    world.run()
    world.fetcher.serve(A, listed[:18])

    held = world.run()

    assert held.status == publish.BRAKE
    assert held.counts["removed"] == 2
    assert len(world.index()) == 20
    assert any(a.startswith("brake: this run would remove 2 of 20") for a in held.alerts)
    assert world.run(anyway=True).status == publish.OK
    assert len(world.index()) == 18


def test_rules_hold_drop_and_correct_entries(world):
    world.source("community", 3, A)
    listed = files(world, 3)
    world.fetcher.serve(A, listed)
    add = "INSERT INTO rules (id, action, match, set_fields, created) VALUES (?, ?, ?, ?, '2026')"
    world.db.execute(add, ("hold", "hold", json.dumps({"manufacturerCode": 0x1000}), "{}"))
    world.db.execute(add, ("drop", "drop", json.dumps({"sha512": listed[1]["sha512"]}), "{}"))
    world.db.execute(
        add, ("fix", "set", json.dumps({"manufacturerCode": 0x1002}), '{"modelId": "Fixed"}')
    )

    report = world.run()

    [e] = world.index()
    assert (e["manufacturerCode"], e["modelId"], e["rules"]) == (0x1002, "Fixed", ["fix"])
    assert len(report.held) == 1 and len(report.dropped) == 1
    assert not (world.site / "images" / listed[0]["sha512"][:16]).exists()


def test_zigpy_sources_download_through_zigpy(world, tmp_path, monkeypatch):
    path = tmp_path / "z.ota"
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
    )

    async def load(config):
        assert config == {"provider": "zigpy_ota", "channel": "stable"}
        return [meta]

    monkeypatch.setattr(sources, "load_zigpy", load)
    world.source(
        "zigpy-ota", 2, type_="zigpy", config={"provider": "zigpy_ota", "channel": "stable"}
    )

    world.run()

    assert [e["modelId"] for e in world.index()] == ["A", "B"]
    assert world.fetcher.calls == []


def test_a_download_that_hangs_fails_alone(world, monkeypatch):
    world.source("community", 3, A)
    listed = files(world, 2)
    world.fetcher.serve(A, listed)
    get = world.fetcher.get

    async def slow(url):
        if url == listed[0]["url"]:
            await asyncio.sleep(10)
        return await get(url)

    monkeypatch.setattr(world.fetcher, "get", slow)
    monkeypatch.setattr(publish, "DOWNLOAD_TIMEOUT", 0.05)

    report = world.run()

    assert len(world.index()) == 1
    assert report.failures[0]["reason"].startswith("TimeoutError")


def test_uploads_are_published_from_the_volume(world):
    world.source("uploads", 1, type_="upload", config={})
    data = ota_file(0x1234, 1, 0x30)
    sha = hashlib.sha512(data).hexdigest()
    (world.uploads / f"{sha}.ota").write_bytes(data)
    fields = {"manufacturer": 0x1234, "image_type": 1, "version": 0x30, "model_id": "M"}
    world.db.execute(
        "INSERT INTO uploads (sha512, file_name, fields, created) VALUES (?, ?, ?, '2026')",
        (sha, "vendor-sent.ota", json.dumps(fields)),
    )
    world.fetcher = publish.HttpFetcher(session=None)

    world.run()

    [e] = world.index()
    assert (e["sources"], e["modelId"], e["sha512"]) == (["uploads"], "M", sha)
    assert world.read(f"images/{sha[:16]}/vendor-sent.ota") == data


def test_a_second_run_waits_for_the_lock(world):
    world.source("community", 3, A)
    world.fetcher.serve(A, files(world, 1))
    assert dbm.take_lock(world.db, "other", dbm.now())

    report = world.run()

    assert report.status == publish.FAILED
    assert report.alerts == ["another run holds the lock"]
    world.clock.advance(hours=7)
    assert world.run().status == publish.OK


def test_the_discord_message_names_the_status_alerts_and_counts(world):
    world.source("community", 3, A)
    report = world.run()
    text = notify.message(report)
    assert text.startswith("Firmware index run 2026-10-30T04:00:00Z: ok\n- source community failed")
    assert "entries 0" in text
    report.alerts = []
    assert notify.message(report) is None
