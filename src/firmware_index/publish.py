"""One publish run: read the sources, check every file, apply the rules, merge, publish."""

import asyncio
import dataclasses
import datetime
import hashlib
import json
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firmware_index import db as dbm
from firmware_index import keys, ota, rules, site, sources
from firmware_index.sources import Candidate
from firmware_index.store import IMMUTABLE, SHORT, Store

OK, BRAKE, FAILED = "ok", "brake", "failed"
LOCKED = "another run holds the lock"
BRAKE_SHARE = 0.05
DOWNLOADS = 4


class Fetcher(Protocol):
    async def get(self, url: str) -> bytes: ...


class HttpFetcher:
    def __init__(self, session):
        self.session = session

    async def get(self, url: str) -> bytes:
        if url.startswith("file:"):
            return await asyncio.to_thread(Path(urlparse(url).path).read_bytes)
        async with self.session.get(url, raise_for_status=True) as r:
            return await r.read()


class CheckError(Exception):
    pass


@dataclass
class Checked:
    sha512: str
    upstream_sha512: str | None
    size: int
    header_string: str
    path: str
    stored: bool


@dataclass
class Report:
    started: str
    status: str = OK
    finished: str | None = None
    snapshot: str | None = None
    changed: bool = False
    counts: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    failures: list = field(default_factory=list)
    clashes: list = field(default_factory=list)
    held: list = field(default_factory=list)
    dropped: list = field(default_factory=list)
    waiting: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    republished: int | None = None


@dataclass
class Settings:
    public_url: str
    key: Ed25519PrivateKey
    store: Store
    anyway: bool = False


def entry_key(c: Candidate) -> str:
    return json.dumps([c.source, list(c.gate()), c.download_key()])


def identity(e: dict) -> tuple:
    return (
        e["sha512"],
        e["manufacturerCode"],
        e["imageType"],
        e["fileVersion"],
        e.get("modelId"),
        tuple(e.get("manufacturerName") or ()),
        e.get("minFileVersion"),
        e.get("maxFileVersion"),
        e.get("hardwareVersionMin"),
        e.get("hardwareVersionMax"),
    )


async def collect(db: sqlite3.Connection, fetcher: Fetcher, uploads: Path, report: Report):
    """Every enabled source's candidates. A source that fails keeps its last good list."""
    out = []
    rows = db.execute("SELECT * FROM sources WHERE enabled = 1 ORDER BY priority").fetchall()
    for row in rows:
        name, prio, config = row["name"], row["priority"], json.loads(row["config"])
        last = json.loads(row["last_candidates"] or "[]")
        try:
            if row["type"] == sources.INDEX:
                found = sources.from_index(name, prio, await fetcher.get(config["url"]))
            elif row["type"] == sources.ZIGPY:
                found = sources.from_zigpy(name, prio, await sources.load_zigpy(config))
            elif row["type"] == sources.UPLOAD:
                uploaded = db.execute("SELECT * FROM uploads").fetchall()
                found = sources.from_uploads(name, prio, uploaded, uploads)
            else:
                raise ValueError(f"unknown source type {row['type']!r}")
            if not found and last and row["type"] != sources.UPLOAD:
                raise ValueError("it returned no entries")
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            kept = [Candidate.from_json(d) for d in last]
            if row["last_error"] is None:
                report.alerts.append(f"source {name} failed: {error}")
            db.execute("UPDATE sources SET last_error = ? WHERE name = ?", (error, name))
            report.sources.append(
                {"name": name, "status": "failed", "error": error, "count": len(kept)}
            )
            for c in kept:
                c.priority = prio
            out.extend(kept)
            continue
        if row["last_error"] is not None:
            report.alerts.append(f"source {name} recovered")
        db.execute(
            "UPDATE sources SET last_ok = ?, last_error = NULL, last_candidates = ? WHERE name = ?",
            (report.started, json.dumps([c.to_json() for c in found]), name),
        )
        report.sources.append({"name": name, "status": "ok", "count": len(found)})
        out.extend(found)
    return out


async def download(c: Candidate, fetcher: Fetcher) -> bytes:
    if c.meta is not None and hasattr(c.meta, "_fetch"):
        # zigpy's own download and checks: its provider's certificates, sizes and checksums.
        data = await c.meta._fetch()
        await c.meta._validate(data)
        return data
    data = await fetcher.get(c.url)
    if c.checksum:
        algorithm, want = c.checksum.split(":", 1)
        if hashlib.new(algorithm, data).hexdigest() != want.lower():
            raise CheckError(f"its {algorithm} does not match the source's")
    return data


def trim(c: Candidate, data: bytes) -> tuple[bytes, ota.Image]:
    try:
        img = ota.find(data)
    except ValueError as e:
        raise CheckError(str(e)) from None
    if (img.manufacturer, img.image_type, img.version) != (c.manufacturer, c.image_type, c.version):
        raise CheckError(
            f"its header names 0x{img.manufacturer:04X}/0x{img.image_type:04X}"
            f" v0x{img.version:08X}, not the entry's"
        )
    return data[img.start : img.end], img


async def check(
    db: sqlite3.Connection, c: Candidate, fetcher: Fetcher, at: str
) -> tuple[Checked, bytes | None]:
    row = db.execute("SELECT * FROM files WHERE download_key = ?", (c.download_key(),)).fetchone()
    if row:
        return (
            Checked(
                sha512=row["sha512"],
                upstream_sha512=row["upstream_sha512"],
                size=row["size"],
                header_string=row["header_string"],
                path=row["path"],
                stored=bool(row["stored"]),
            ),
            None,
        )
    data = await download(c, fetcher)
    body, img = trim(c, data)
    sha = hashlib.sha512(body).hexdigest()
    upstream = hashlib.sha512(data).hexdigest() if body != data else None
    chk = Checked(
        sha512=sha,
        upstream_sha512=upstream,
        size=len(body),
        header_string=img.header_string,
        path=f"images/{sha[:16]}/{c.file_name}",
        stored=False,
    )
    db.execute(
        "INSERT OR REPLACE INTO files (download_key, sha512, upstream_sha512, size,"
        " header_string, path, stored, checked) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        (c.download_key(), sha, upstream, len(body), img.header_string, chk.path, at),
    )
    return chk, body


async def store_file(
    db: sqlite3.Connection, s: Settings, c: Candidate, chk: Checked, body, fetcher
) -> None:
    if chk.stored:
        return
    if body is None:
        body, _ = trim(c, await download(c, fetcher))
        if hashlib.sha512(body).hexdigest() != chk.sha512:
            raise CheckError("it changed since it was checked")
    if not await asyncio.to_thread(s.store.exists, chk.path):
        await asyncio.to_thread(s.store.put, chk.path, body, "application/octet-stream", IMMUTABLE)
    db.execute("UPDATE files SET stored = 1 WHERE download_key = ?", (c.download_key(),))
    chk.stored = True


def with_fields(c: Candidate, fields: dict) -> tuple[Candidate, str | None]:
    header = fields.get("otaHeaderString")
    changes = {
        rules.SETTABLE[k]: v for k, v in fields.items() if rules.SETTABLE[k] != "header_string"
    }
    return dataclasses.replace(c, **changes), header


def entry(c: Candidate, chk: Checked, header: str | None, srcs, applied, seen, base) -> dict:
    e = {
        "fileName": c.file_name,
        "fileVersion": c.version,
        "fileSize": chk.size,
        "url": f"{base}/{chk.path}",
        "imageType": c.image_type,
        "manufacturerCode": c.manufacturer,
        "sha512": chk.sha512,
        "otaHeaderString": header if header is not None else chk.header_string,
    }
    optional = {
        "releaseNotes": c.release_notes,
        "modelId": c.model_id,
        "manufacturerName": c.manufacturer_names,
        "hardwareVersionMin": c.hardware_min,
        "hardwareVersionMax": c.hardware_max,
        "minFileVersion": c.min_file_version,
        "maxFileVersion": c.max_file_version,
        "originalUrl": c.original_url,
        "sources": srcs,
        "upstreamSha512": chk.upstream_sha512,
        "rules": applied or None,
        "firstSeen": seen,
    }
    e.update({k: v for k, v in optional.items() if v is not None})
    return e


def sort_key(e: dict) -> tuple:
    return (
        e["manufacturerCode"],
        e["imageType"],
        e["fileVersion"],
        e.get("modelId") or "",
        json.dumps(e.get("manufacturerName") or []),
        e["sha512"],
    )


async def build(db, s: Settings, fetcher: Fetcher, uploads: Path, at, report: Report):
    """The entries this run would publish."""
    stamp = dbm.iso(at)
    candidates = await collect(db, fetcher, uploads, report)
    delays = {
        r["name"]: r["delay_days"] for r in db.execute("SELECT name, delay_days FROM sources")
    }
    active = [
        rules.Rule(
            id=r["id"],
            action=r["action"],
            match=json.loads(r["match"]),
            set=json.loads(r["set_fields"]),
            note=r["note"],
            enabled=bool(r["enabled"]),
        )
        for r in db.execute("SELECT * FROM rules ORDER BY created, id")
    ]

    ready = []
    for c in candidates:
        key = entry_key(c)
        db.execute("INSERT OR IGNORE INTO seen (entry_key, first_seen) VALUES (?, ?)", (key, stamp))
        first = db.execute("SELECT first_seen FROM seen WHERE entry_key = ?", (key,)).fetchone()[0]
        wait = datetime.timedelta(days=delays.get(c.source, 0))
        if at - datetime.datetime.fromisoformat(first.replace("Z", "+00:00")) < wait:
            report.waiting.append(c.describe())
            continue
        ready.append((c, first))

    gate = asyncio.Semaphore(DOWNLOADS)
    # One file can stand behind several candidates (a model each); fetch it once.
    per_file = defaultdict(asyncio.Lock)

    async def one(c: Candidate, first: str):
        async with gate, per_file[c.download_key()]:
            try:
                chk, body = await check(db, c, fetcher, stamp)
                outcome = rules.apply(active, c, chk.sha512, chk.upstream_sha512)
                if outcome.action == rules.DROP:
                    report.dropped.append(c.describe())
                    return None
                if outcome.action == rules.HOLD:
                    report.held.append(c.describe())
                    return None
                await store_file(db, s, c, chk, body, fetcher)
            except Exception as e:
                reason = str(e) if isinstance(e, CheckError) else f"{type(e).__name__}: {e}"
                report.failures.append({"entry": c.describe(), "reason": reason})
                return None
            fixed, header = with_fields(c, outcome.fields)
            return fixed, chk, header, outcome.applied, first

    done = [r for r in await asyncio.gather(*(one(c, f) for c, f in ready)) if r]

    groups = defaultdict(list)
    for item in done:
        groups[item[0].gate()].append(item)
    entries = []
    for items in groups.values():
        items.sort(key=lambda i: (i[0].priority, i[0].source))
        win, chk, header, applied, first = items[0]
        srcs = sorted({i[0].source for i in items if i[1].sha512 == chk.sha512})
        losers = [i for i in items if i[1].sha512 != chk.sha512]
        if losers:
            report.clashes.append(
                {
                    "entry": win.describe(),
                    "kept": f"{win.source} {chk.sha512[:16]}",
                    "over": [f"{i[0].source} {i[1].sha512[:16]}" for i in losers],
                }
            )
        firsts = [i[4] for i in items if i[1].sha512 == chk.sha512]
        entries.append(entry(win, chk, header, srcs, applied, min(firsts), s.public_url))
    entries.sort(key=sort_key)
    return entries


def serialize(entries: list[dict]) -> bytes:
    return (json.dumps(entries, indent=2, ensure_ascii=False) + "\n").encode()


async def run(db: sqlite3.Connection, s: Settings, fetcher: Fetcher, uploads: Path) -> Report:
    at = dbm.now()
    report = Report(started=dbm.iso(at))
    holder = uuid.uuid4().hex
    if not dbm.take_lock(db, holder, at):
        report.status = FAILED
        report.alerts.append(LOCKED)
        return report
    run_id = db.execute(
        "INSERT INTO runs (started, anyway) VALUES (?, ?)", (report.started, int(s.anyway))
    ).lastrowid
    try:
        entries = await build(db, s, fetcher, uploads, at, report)
        await publish(db, s, entries, at, report, run_id)
    except asyncio.CancelledError:
        report.status = FAILED
        report.alerts.append("the run was stopped before it finished")
        raise
    except Exception as e:
        report.status = FAILED
        report.alerts.append(f"run failed: {type(e).__name__}: {e}")
    finally:
        report.finished = dbm.iso(dbm.now())
        db.execute(
            "UPDATE runs SET finished = ?, status = ?, report = ? WHERE id = ?",
            (report.finished, report.status, json.dumps(dataclasses.asdict(report)), run_id),
        )
        dbm.release_lock(db, holder)
    return report


def compare(before: list[dict], entries: list[dict], report: Report) -> int:
    """Fill the report's counts against the published index; returns how many entries go."""
    old, new = {identity(e) for e in before}, {identity(e) for e in entries}
    report.counts = {
        "entries": len(entries),
        "added": len(new - old),
        "removed": len(old - new),
        "failed": len(report.failures),
        "held": len(report.held),
        "dropped": len(report.dropped),
        "waiting": len(report.waiting),
        "clashes": len(report.clashes),
    }
    return len(old - new)


def keep(db, run_id: int, entries: list[dict]) -> tuple[bytes, str]:
    """Store the index a run built, published or not, so it can be published later."""
    body = serialize(entries)
    sha = hashlib.sha512(body).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO snapshots (sha512, entries, created) VALUES (?, ?, ?)",
        (sha, json.dumps(entries), dbm.iso(dbm.now())),
    )
    db.execute("UPDATE runs SET result_sha512 = ? WHERE id = ?", (sha, run_id))
    return body, sha


async def publish(db, s: Settings, entries: list[dict], at, report: Report, run_id: int) -> None:
    last = db.execute("SELECT * FROM published WHERE id = 1").fetchone()
    before = json.loads(last["entries"]) if last else []
    removed = compare(before, entries, report)
    if not entries and not before:
        report.status = FAILED
        report.alerts.append("no entries to publish, and nothing was published before")
        return
    body, sha = keep(db, run_id, entries)
    if before and removed > BRAKE_SHARE * len(before) and not s.anyway:
        report.status = BRAKE
        report.alerts.append(
            f"brake: this run would remove {removed} of {len(before)} entries;"
            " the last index stays"
        )
        return
    await write(db, s, entries, body, sha, at, report, last)


async def write(db, s: Settings, entries, body: bytes, sha: str, at, report: Report, last) -> None:
    put = s.store.put
    if last is None or last["sha512"] != sha:
        # A new path even for an index published before: a reader only moves forward.
        snapshot = f"snapshots/{at.strftime('%Y%m%dT%H%M%SZ')}.json"
        await asyncio.to_thread(put, snapshot, body, "application/json", IMMUTABLE)
        db.execute(
            "INSERT OR REPLACE INTO published (id, snapshot, sha512, entries, at)"
            " VALUES (1, ?, ?, ?, ?)",
            (snapshot, sha, json.dumps(entries), report.started),
        )
        report.changed = True
    else:
        snapshot = last["snapshot"]
    report.snapshot = snapshot

    public = keys.public_hex(s.key)
    latest = {
        "snapshot": snapshot,
        "sha512": sha,
        "signature": keys.sign(s.key, f"{snapshot}\n{sha}".encode()),
        "checked": report.started,
    }
    page = site.render(entries, snapshot, report.started, public, s.public_url)
    await asyncio.to_thread(put, "signing-key.pub", (public + "\n").encode(), "text/plain", SHORT)
    await asyncio.to_thread(put, "index.html", page.encode(), "text/html; charset=utf-8", SHORT)
    await asyncio.to_thread(put, "index.json", body, "application/json", SHORT)
    latest_body = (json.dumps(latest, indent=2) + "\n").encode()
    await asyncio.to_thread(put, "latest.json", latest_body, "application/json", SHORT)


async def republish(db, s: Settings, source_run: int) -> Report:
    """Publish the index an earlier run built: a rollback, or a run the brake held."""
    at = dbm.now()
    report = Report(started=dbm.iso(at), republished=source_run)
    row = db.execute(
        "SELECT snapshots.entries FROM runs JOIN snapshots"
        " ON snapshots.sha512 = runs.result_sha512 WHERE runs.id = ?",
        (source_run,),
    ).fetchone()
    if row is None:
        report.status = FAILED
        report.alerts.append(f"run #{source_run} kept no index to publish")
        return report
    holder = uuid.uuid4().hex
    if not dbm.take_lock(db, holder, at):
        report.status = FAILED
        report.alerts.append(LOCKED)
        return report
    run_id = db.execute(
        "INSERT INTO runs (started, anyway) VALUES (?, 1)", (report.started,)
    ).lastrowid
    try:
        entries = json.loads(row["entries"])
        last = db.execute("SELECT * FROM published WHERE id = 1").fetchone()
        compare(json.loads(last["entries"]) if last else [], entries, report)
        body, sha = keep(db, run_id, entries)
        await write(db, s, entries, body, sha, at, report, last)
    except Exception as e:
        report.status = FAILED
        report.alerts.append(f"publish failed: {type(e).__name__}: {e}")
    finally:
        report.finished = dbm.iso(dbm.now())
        db.execute(
            "UPDATE runs SET finished = ?, status = ?, report = ? WHERE id = ?",
            (report.finished, report.status, json.dumps(dataclasses.asdict(report)), run_id),
        )
        dbm.release_lock(db, holder)
    return report
