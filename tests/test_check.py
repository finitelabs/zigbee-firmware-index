import asyncio
import datetime
import json

from conftest import index_entry, ota_file

from firmware_index import check, keys

BASE = "https://ota.example.test"
A = "https://a.test/index.json"


class SiteFetcher:
    def __init__(self, site):
        self.site = site

    async def get(self, url):
        return (self.site / url.removeprefix(BASE + "/")).read_bytes()


def published(world):
    world.source("community", 3, A)
    data = ota_file(0x1234, 1, 0x20)
    world.fetcher.serve("https://a.test/fw.ota", data)
    world.fetcher.serve(A, [index_entry("https://a.test/fw.ota", data, 0x1234, 1, 0x20)])
    world.run()
    return SiteFetcher(world.site)


def found(world, fetcher, hours=1, pinned=None):
    now = world.clock.at + datetime.timedelta(hours=hours)
    return asyncio.run(check.problems(BASE, fetcher, now, pinned))


def test_a_fresh_site_passes(world):
    fetcher = published(world)
    assert found(world, fetcher) == []
    assert found(world, fetcher, pinned=world.public) == []


def test_a_site_whose_runs_stopped_fails_after_48_hours(world):
    fetcher = published(world)
    assert found(world, fetcher, hours=48) == []
    assert "over 48 hours ago" in found(world, fetcher, hours=49)[0]


def test_a_changed_snapshot_or_signature_fails(world):
    fetcher = published(world)
    latest = json.loads(world.read("latest.json"))
    (world.site / latest["snapshot"]).write_bytes(b"[]\n")
    problems = found(world, fetcher)
    assert any("does not match the sha512" in p for p in problems)

    latest["sha512"] = "0" * 128
    (world.site / "latest.json").write_text(json.dumps(latest))
    assert any("signature does not verify" in p for p in found(world, fetcher))


def test_a_key_other_than_the_pinned_one_fails(world, tmp_path):
    fetcher = published(world)
    other = keys.generate(tmp_path / "other.pem")
    problems = found(world, fetcher, pinned=other)
    assert "signing-key.pub is not the pinned public key" in problems
    assert "latest.json's signature does not verify" in problems


def test_an_unreachable_site_fails(world):
    fetcher = published(world)
    (world.site / "latest.json").unlink()
    assert found(world, fetcher)[0].startswith("could not read the site")
