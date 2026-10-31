import asyncio
import datetime
import hashlib
import json
import struct

import pytest

from firmware_index import db as dbm
from firmware_index import keys, publish
from firmware_index.store import DirStore

START = datetime.datetime(2026, 10, 30, 4, 0, tzinfo=datetime.UTC)


def ota_file(mfr, itype, version, payload=b"firmware" * 16, prefix=b"", suffix=b""):
    """A spec OTA file: a 56-byte header and one upgrade image subelement."""
    image_size = 56 + 6 + len(payload)
    header = struct.pack(
        "<IHHHHHIH32sI",
        0x0BEEF11E,
        0x0100,
        56,
        0,
        mfr,
        itype,
        version,
        2,
        b"Test image".ljust(32, b"\0"),
        image_size,
    )
    return prefix + header + struct.pack("<HI", 0, len(payload)) + payload + suffix


def index_entry(url, data, mfr, itype, version, **extra):
    return {
        "fileName": url.rsplit("/", 1)[-1],
        "fileVersion": version,
        "fileSize": len(data),
        "url": url,
        "imageType": itype,
        "manufacturerCode": mfr,
        "sha512": hashlib.sha512(data).hexdigest(),
        "otaHeaderString": "Test image",
        **extra,
    }


class FakeFetcher:
    def __init__(self):
        self.files = {}
        self.calls = []

    def serve(self, url, body):
        self.files[url] = body if isinstance(body, bytes) else json.dumps(body).encode()

    async def get(self, url):
        self.calls.append(url)
        if url not in self.files:
            raise OSError(f"{url} is unreachable")
        return self.files[url]


class Clock:
    def __init__(self, monkeypatch):
        self.at = START
        monkeypatch.setattr(dbm, "now", lambda: self.at)

    def advance(self, **delta):
        self.at += datetime.timedelta(**delta)


class World:
    def __init__(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.db = dbm.connect(tmp_path / "index.sqlite3")
        self.db.execute("DELETE FROM sources")
        self.fetcher = FakeFetcher()
        self.clock = Clock(monkeypatch)
        self.site = tmp_path / "site"
        self.uploads = tmp_path / "uploads"
        self.uploads.mkdir()
        keys.generate(tmp_path / "key.pem")
        self.key = keys.load(tmp_path / "key.pem")
        self.public = keys.public_hex(self.key)
        self.store = DirStore(self.site)

    def source(self, name, priority, url=None, delay_days=0, type_="index", config=None):
        config = config if config is not None else {"url": url}
        self.db.execute(
            "INSERT INTO sources (name, type, config, priority, delay_days) VALUES (?, ?, ?, ?, ?)",
            (name, type_, json.dumps(config), priority, delay_days),
        )

    def run(self, anyway=False):
        settings = publish.Settings(
            public_url="https://ota.example.test", key=self.key, store=self.store, anyway=anyway
        )
        return asyncio.run(publish.run(self.db, settings, self.fetcher, self.uploads))

    def read(self, key):
        return (self.site / key).read_bytes()

    def index(self):
        return json.loads(self.read("index.json"))


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)
