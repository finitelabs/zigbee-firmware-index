"""The admin page: runs, sources, images, rules, uploads and the audit log."""

import asyncio
import contextlib
import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

import aiohttp
import yaml
from starlette.applications import Starlette
from starlette.datastructures import Headers, UploadFile
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from firmware_index import db as dbm
from firmware_index import ota, publish, rules, runner, sources

EMAIL_HEADER = "x-auth-request-email"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_UPLOAD = 16 * 1024 * 1024
LIST_LIMIT = 200
PENDING_SECONDS = 24 * 3600
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent / "templates")
TEMPLATES.env.filters["hex4"] = lambda n: f"0x{n:04X}" if isinstance(n, int) else ""
TEMPLATES.env.filters["hex8"] = lambda n: f"0x{n:08X}" if isinstance(n, int) else ""
TEMPLATES.env.filters["when"] = lambda t: t.replace("T", " ")[:16] + " UTC" if t else ""

# zigpy's providers that list files on their own. Of its others, salus, thirdreality and inovelli
# are stubs that list nothing, and the local ones and zigpy_remote need a folder or URL given.
PROVIDERS = {
    "zigpy_ota": "zigpy-ota",
    "z2m": "Community index (zigpy)",
    "ledvance": "Ledvance",
    "sonoff": "Sonoff",
    "ikea": "IKEA",
}
CHANNELS = ["stable", "beta", "dev"]
HEX4 = {"manufacturerCode", "imageType", "manufacturer", "image_type"}
HEX8 = {
    "fileVersion",
    "version",
    "minFileVersion",
    "maxFileVersion",
    "min_file_version",
    "max_file_version",
}
SHAS = {"sha512", "upstreamSha512"}


def show(key: str, value) -> str:
    """A stored value as the page shows it: codes in hex, lists joined, long text cut short."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict) and value and set(value) <= {"min", "max"}:
        low = show(key, value["min"]) if "min" in value else "any"
        high = show(key, value["max"]) if "max" in value else "any"
        return f"{low} to {high}"
    if isinstance(value, dict):
        return ", ".join(f"{k} {v}" for k, v in pairs(value))
    if isinstance(value, int) and key in HEX4:
        return f"0x{value:04X}"
    if isinstance(value, int) and key in HEX8:
        return f"0x{value:08X}"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, str) and key in SHAS:
        return value[:16] + "..."
    text = value if isinstance(value, str) else json.dumps(value)
    return text if len(text) <= 80 else text[:77] + "..."


def pairs(d: dict | None) -> list[tuple[str, str]]:
    return [(k, show(k, v)) for k, v in (d or {}).items() if v not in (None, "", [], {})]


TEMPLATES.env.filters["pairs"] = pairs


class Refused(Exception):
    pass


class Guard:
    """Only the listed emails, and a form only from this site's own pages. Run locally, the one
    local user stands in for the sign-in proxy's header."""

    def __init__(self, app, emails: set[str], local_user: str | None = None):
        self.app = app
        self.emails = emails
        self.local_user = local_user

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/healthz":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        # Run locally there is no sign-in, so only this machine's own names may reach the page;
        # a site rebinding its name to 127.0.0.1 would otherwise pass every check.
        if self.local_user and urlparse(f"//{headers.get('host', '')}").hostname not in LOCAL_HOSTS:
            return await PlainTextResponse("Not allowed", 403)(scope, receive, send)
        email = self.local_user or headers.get(EMAIL_HEADER, "").strip().lower()
        if email not in self.emails:
            return await PlainTextResponse("Not allowed", 403)(scope, receive, send)
        if scope["method"] == "POST":
            # The proxy's sign-in rides on a cookie, so a form from another site must not count.
            origin = headers.get("origin") or headers.get("referer") or ""
            if urlparse(origin).netloc != headers.get("host"):
                return await PlainTextResponse("Cross-site form refused", 403)(scope, receive, send)
        state = scope.setdefault("state", {})
        state["user"] = email
        try:
            return await self.app(scope, receive, send)
        finally:
            if "db" in state:
                state["db"].close()


def open_db(request: Request) -> sqlite3.Connection:
    """One connection per request; Guard closes it."""
    if "db" not in request.scope.setdefault("state", {}):
        request.scope["state"]["db"] = dbm.connect(request.app.state.db_path)
    return request.scope["state"]["db"]


def page(request: Request, name: str, status_code: int = 200, **context) -> Response:
    context.setdefault("message", request.query_params.get("message"))
    return TEMPLATES.TemplateResponse(
        request, name, {"user": request.state.user, **context}, status_code=status_code
    )


def back(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"{path}?{urlencode({'message': message})}", status_code=303)


def default(value: int | None, fallback: int) -> int:
    return fallback if value is None else value


def optional_int(value: str | None) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        raise Refused(f"{value!r} is not a number (decimal, or hex as 0x...)") from None


async def healthz(request: Request) -> Response:
    dbm.connect(request.app.state.db_path).close()
    return PlainTextResponse("ok")


async def runs_page(request: Request) -> Response:
    db = open_db(request)
    rows = db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 30").fetchall()
    published = db.execute(
        "SELECT snapshot, sha512, at, json_array_length(entries) AS count"
        " FROM published WHERE id = 1"
    ).fetchone()
    shown = with_actions(db, [{**dict(r), "report": json.loads(r["report"] or "{}")} for r in rows])
    # Waiting comes from the last run that read the sources; a republish reads none.
    read = next(
        (r for r in shown if r["report"].get("counts") and not r["report"].get("republished")),
        None,
    )
    on, at = runner.schedule(db)
    now = dbm.now()
    upcoming = None
    if on:
        upcoming = dbm.iso(runner.next_run(at, now, dbm.get_setting(db, "schedule_last")))
    return page(
        request,
        "runs.html",
        runs=shown,
        published=published,
        waiting=read["report"]["counts"]["waiting"] if read else None,
        schedule_on=on,
        schedule_at=at,
        upcoming=upcoming,
    )


async def save_schedule(request: Request) -> Response:
    form = await request.form()
    at = (form.get("at") or "").strip()
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", at):
        return back("/", "Give the time as HH:MM, in UTC")
    on = form.get("on") == "1"
    db = open_db(request)
    dbm.set_setting(db, "schedule_at", at)
    dbm.set_setting(db, "schedule_on", "1" if on else "0")
    dbm.audit(db, request.state.user, "schedule", {"at": at, "on": on})
    return back("/", f"Runs every day at {at} UTC" if on else "Scheduled runs are off")


def with_actions(db, runs: list[dict]) -> list[dict]:
    """Mark the run whose index is live, and what each other run offers: a braked run's index
    can be published, and an earlier published one rolled back to."""
    row = db.execute("SELECT sha512 FROM published WHERE id = 1").fetchone()
    live = row["sha512"] if row else None
    marked = False
    for r in runs:
        r["action"] = None
        if not r.get("result_sha512") or r["status"] not in ("ok", "brake"):
            continue
        if r["result_sha512"] == live:
            r["action"] = None if marked else "live"
            marked = True
        else:
            r["action"] = "publish" if r["status"] == "brake" else "rollback"
    return runs


def run_row(db, run_id) -> dict | None:
    row = db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return {**dict(row), "report": json.loads(row["report"] or "{}")} if row else None


async def run_detail(request: Request) -> Response:
    db = open_db(request)
    run = run_row(db, request.path_params["id"])
    if run is None:
        return PlainTextResponse("No such run", 404)
    newest = db.execute(
        "SELECT * FROM runs WHERE result_sha512 = ? ORDER BY id DESC LIMIT 1",
        (run.get("result_sha512"),),
    ).fetchone()
    others = [{**dict(newest), "report": {}}] if newest and newest["id"] != run["id"] else []
    with_actions(db, others + [run])
    return page(request, "run.html", run=run, report=run["report"])


async def publish_now(request: Request) -> Response:
    try:
        await request.app.state.runs.start(False)
    except Exception as e:
        return back("/", f"Could not start a run: {e}")
    dbm.audit(open_db(request), request.state.user, "publish", {})
    return back("/", "Started a run; refresh to follow it")


def describe(e: dict) -> str:
    model = f" {e['modelId']}" if e.get("modelId") else ""
    return f"{e['fileName']} ({e['manufacturerCode']:04X}/{e['imageType']:04X}{model})"


async def confirm_publish(request: Request) -> Response:
    db = open_db(request)
    run = run_row(db, request.path_params["id"])
    if run is None:
        return PlainTextResponse("No such run", 404)
    with_actions(db, [run])
    if run["action"] not in ("publish", "rollback"):
        return back(f"/runs/{run['id']}", "This run's index is live, or it kept none to publish")
    kept = db.execute(
        "SELECT entries FROM snapshots WHERE sha512 = ?", (run["result_sha512"],)
    ).fetchone()
    live = db.execute("SELECT entries FROM published WHERE id = 1").fetchone()
    entries = json.loads(kept["entries"])
    before = json.loads(live["entries"]) if live else []
    old = {publish.identity(e): e for e in before}
    new = {publish.identity(e): e for e in entries}
    added = [describe(new[k]) for k in new.keys() - old.keys()]
    removed = [describe(old[k]) for k in old.keys() - new.keys()]
    return page(
        request,
        "publish.html",
        run=run,
        count=len(entries),
        live=len(before),
        added=sorted(added),
        removed=sorted(removed),
    )


async def publish_run(request: Request) -> Response:
    db = open_db(request)
    run = run_row(db, request.path_params["id"])
    if run is None:
        return PlainTextResponse("No such run", 404)
    with_actions(db, [run])
    form = await request.form()
    if run["action"] not in ("publish", "rollback"):
        return back(f"/runs/{run['id']}", "This run's index is live, or it kept none to publish")
    if run["action"] == "publish" and (form.get("confirm") or "").strip() != "publish":
        return back(f"/runs/{run['id']}/publish", "Type publish to confirm")
    try:
        await request.app.state.runs.republish(run["id"])
    except Exception as e:
        return back(f"/runs/{run['id']}", f"Could not publish: {e}")
    dbm.audit(db, request.state.user, run["action"], {"run": run["id"]})
    done = "Rolled back to" if run["action"] == "rollback" else "Published"
    return back("/", f"{done} run #{run['id']}'s index")


async def sources_page(request: Request) -> Response:
    rows = open_db(request).execute("SELECT * FROM sources ORDER BY priority").fetchall()
    shown = [
        {
            **dict(r),
            "config": json.loads(r["config"]),
            "candidates": len(json.loads(r["last_candidates"] or "[]")),
        }
        for r in rows
    ]
    return page(
        request,
        "sources.html",
        sources=shown,
        types=[sources.INDEX, sources.ZIGPY, sources.UPLOAD],
        providers=PROVIDERS,
        channels=CHANNELS,
    )


def source_fields(form) -> dict:
    kind = form.get("type")
    if kind == sources.INDEX:
        url = (form.get("url") or "").strip()
        if not url.startswith("https://"):
            raise Refused("An index source needs an https:// URL")
        config = {"url": url}
    elif kind == sources.ZIGPY:
        provider = form.get("provider")
        if provider not in PROVIDERS:
            raise Refused("Choose one of zigpy's providers")
        config = {"provider": provider}
        if provider == "zigpy_ota":
            channel = form.get("channel") or "stable"
            if channel not in CHANNELS:
                raise Refused(f"Unknown channel {channel!r}")
            config["channel"] = channel
    elif kind == sources.UPLOAD:
        config = {}
    else:
        raise Refused(f"Unknown type {kind!r}")
    return {
        "type": kind,
        "config": json.dumps(config),
        "priority": default(optional_int(form.get("priority")), 10),
        "delay_days": default(optional_int(form.get("delay_days")), 0),
        "enabled": int(form.get("enabled") == "1"),
    }


async def add_source(request: Request) -> Response:
    form = await request.form()
    name = (form.get("name") or "").strip()
    try:
        if not RULE_ID.match(name):
            raise Refused("A name is letters, digits, dots, dashes and underscores")
        f = source_fields(form)
    except (Refused, ValueError) as e:
        return back("/sources", str(e))
    db = open_db(request)
    try:
        db.execute(
            "INSERT INTO sources (name, type, config, priority, delay_days, enabled)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (name, f["type"], f["config"], f["priority"], f["delay_days"], f["enabled"]),
        )
    except sqlite3.IntegrityError:
        return back("/sources", f"A source named {name} exists")
    dbm.audit(db, request.state.user, "source.add", {"name": name, **f})
    return back("/sources", f"Added {name}")


async def edit_source(request: Request) -> Response:
    name = request.path_params["name"]
    form = await request.form()
    try:
        f = source_fields(form)
    except (Refused, ValueError) as e:
        return back("/sources", str(e))
    db = open_db(request)
    db.execute(
        "UPDATE sources SET type = ?, config = ?, priority = ?, delay_days = ?, enabled = ?"
        " WHERE name = ?",
        (f["type"], f["config"], f["priority"], f["delay_days"], f["enabled"], name),
    )
    dbm.audit(db, request.state.user, "source.edit", {"name": name, **f})
    return back("/sources", f"Saved {name}")


def search_text(e: dict) -> str:
    parts = [
        f"{e['manufacturerCode']:04x}",
        f"{e['imageType']:04x}",
        f"{e['fileVersion']:08x}",
        e["fileName"],
        e.get("modelId") or "",
        " ".join(e.get("manufacturerName") or []),
        " ".join(e.get("sources") or []),
        e.get("originalUrl") or "",
        e.get("otaHeaderString") or "",
        e.get("releaseNotes") or "",
    ]
    return " ".join(parts).lower()


async def images(request: Request) -> Response:
    db = open_db(request)
    row = db.execute("SELECT entries FROM published WHERE id = 1").fetchone()
    entries = json.loads(row["entries"]) if row else []
    q = request.query_params.get("q", "").strip()
    terms = q.lower().split()
    found = [e for e in entries if all(t in search_text(e) for t in terms)]
    last = db.execute(
        "SELECT report FROM runs WHERE report IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    report = json.loads(last["report"]) if last else {}
    return page(
        request,
        "images.html",
        q=q,
        total=len(found),
        entries=found[:LIST_LIMIT],
        limit=LIST_LIMIT,
        report=report,
    )


async def image_detail(request: Request) -> Response:
    sha = request.path_params["sha"]
    db = open_db(request)
    row = db.execute("SELECT entries FROM published WHERE id = 1").fetchone()
    entries = [e for e in json.loads(row["entries"]) if e["sha512"] == sha] if row else []
    if not entries:
        holding = [
            {**dict(r), "match": json.loads(r["match"])}
            for r in db.execute("SELECT * FROM rules WHERE action IN ('hold', 'drop')")
            if json.loads(r["match"]).get("sha512") == sha
        ]
        return page(request, "image_gone.html", sha=sha, rules=holding, status_code=404)
    return page(request, "image.html", entries=entries, sha=sha, settable=list(rules.SETTABLE))


def new_rule_id(db: sqlite3.Connection, base: str) -> str:
    rid, n = base, 1
    while db.execute("SELECT 1 FROM rules WHERE id = ?", (rid,)).fetchone():
        n += 1
        rid = f"{base}-{n}"
    return rid


def save_rule(db, who: str, rule: rules.Rule) -> None:
    db.execute(
        "INSERT INTO rules (id, action, match, set_fields, note, enabled, author, created)"
        " VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (
            rule.id,
            rule.action,
            json.dumps(rule.match),
            json.dumps(rule.set),
            rule.note,
            who,
            dbm.iso(dbm.now()),
        ),
    )
    dbm.audit(
        db,
        who,
        "rule.add",
        {"id": rule.id, "action": rule.action, "match": rule.match, "set": rule.set},
    )


def set_fields(form) -> dict:
    """The set fields a form fills in, named s_<field>."""
    fields = {}
    for name in rules.SETTABLE:
        value = (form.get(f"s_{name}") or "").strip()
        if not value:
            continue
        if name == "manufacturerName":
            fields[name] = [v.strip() for v in value.split(",") if v.strip()]
        elif name in ("releaseNotes", "modelId", "otaHeaderString"):
            fields[name] = value
        else:
            fields[name] = optional_int(value)
    if not fields:
        raise Refused("Give at least one field to set")
    return fields


def match_fields(form) -> dict:
    """What a rule matches, from fields named m_<key>."""
    match = {}
    sha = (form.get("m_sha512") or "").strip().lower()
    if sha:
        if not SHA512.match(sha):
            raise Refused("A sha512 is 128 hex digits")
        match["sha512"] = sha
    if form.get("m_source"):
        match["source"] = form.get("m_source")
    for key in ("manufacturerCode", "imageType"):
        value = optional_int(form.get(f"m_{key}"))
        if value is not None:
            match[key] = value
    low, high = optional_int(form.get("m_versionMin")), optional_int(form.get("m_versionMax"))
    if low is not None and low == high:
        match["fileVersion"] = low
    elif low is not None or high is not None:
        match["fileVersion"] = {k: v for k, v in (("min", low), ("max", high)) if v is not None}
    for key in ("modelId", "url"):
        value = (form.get(f"m_{key}") or "").strip()
        if value:
            match[key] = value
    if not match:
        raise Refused("Give at least one thing to match; for every file, use the URL pattern *")
    return match


async def image_rule(request: Request) -> Response:
    sha = request.path_params["sha"]
    if not SHA512.match(sha):
        return PlainTextResponse("Not a sha512", 400)
    form = await request.form()
    action = form.get("action")
    try:
        fields = set_fields(form) if action == rules.SET else {}
        db = open_db(request)
        rule = rules.Rule(
            id=new_rule_id(db, f"{action}-{sha[:12]}"),
            action=action,
            match={"sha512": sha},
            set=fields,
            note=(form.get("note") or "").strip(),
        )
    except (Refused, ValueError) as e:
        return back(f"/images/{sha}", str(e))
    save_rule(db, request.state.user, rule)
    return back("/rules", f"Added rule {rule.id}; it applies from the next run")


async def rules_page(request: Request) -> Response:
    db = open_db(request)
    rows = db.execute("SELECT * FROM rules ORDER BY created, id").fetchall()
    shown = [
        {**dict(r), "match": json.loads(r["match"]), "set": json.loads(r["set_fields"])}
        for r in rows
    ]
    names = [r["name"] for r in db.execute("SELECT name FROM sources ORDER BY priority")]
    return page(
        request,
        "rules.html",
        rules=shown,
        actions=[rules.HOLD, rules.DROP, rules.SET],
        sources=names,
        settable=list(rules.SETTABLE),
    )


async def add_rule(request: Request) -> Response:
    form = await request.form()
    db = open_db(request)
    try:
        rid = (form.get("id") or "").strip()
        if not RULE_ID.match(rid):
            raise Refused("An id is letters, digits, dots, dashes and underscores")
        if db.execute("SELECT 1 FROM rules WHERE id = ?", (rid,)).fetchone():
            raise Refused(f"A rule {rid} exists")
        action = form.get("action")
        rule = rules.Rule(
            id=rid,
            action=action,
            match=match_fields(form),
            set=set_fields(form) if action == rules.SET else {},
            note=(form.get("note") or "").strip(),
        )
    except (Refused, ValueError) as e:
        return back("/rules", str(e))
    save_rule(db, request.state.user, rule)
    return back("/rules", f"Added rule {rid}; it applies from the next run")


async def toggle_rule(request: Request) -> Response:
    rid = request.path_params["id"]
    db = open_db(request)
    db.execute("UPDATE rules SET enabled = 1 - enabled WHERE id = ?", (rid,))
    row = db.execute("SELECT enabled FROM rules WHERE id = ?", (rid,)).fetchone()
    if row is None:
        return back("/rules", f"No rule {rid}")
    dbm.audit(db, request.state.user, "rule.toggle", {"id": rid, "enabled": row["enabled"]})
    return back("/rules", f"Rule {rid} is {'on' if row['enabled'] else 'off'}")


async def delete_rule(request: Request) -> Response:
    rid = request.path_params["id"]
    db = open_db(request)
    row = db.execute("SELECT * FROM rules WHERE id = ?", (rid,)).fetchone()
    if row is None:
        return back("/rules", f"No rule {rid}")
    db.execute("DELETE FROM rules WHERE id = ?", (rid,))
    dbm.audit(db, request.state.user, "rule.delete", dict(row))
    return back("/rules", f"Deleted rule {rid}")


async def rules_yaml(request: Request) -> Response:
    rows = open_db(request).execute("SELECT * FROM rules ORDER BY created, id").fetchall()
    out = []
    for r in rows:
        rule = {"id": r["id"], "match": json.loads(r["match"]), "action": r["action"]}
        if r["action"] == rules.SET:
            rule["set"] = json.loads(r["set_fields"])
        rule.update({"note": r["note"], "enabled": bool(r["enabled"]), "author": r["author"]})
        rule["created"] = r["created"]
        out.append(rule)
    return Response(
        yaml.safe_dump(out, sort_keys=False, allow_unicode=True),
        media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="rules.yaml"'},
    )


def upload_dirs(request: Request) -> tuple[Path, Path]:
    done = request.app.state.uploads
    pending = done / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    stale = time.time() - PENDING_SECONDS
    for f in pending.iterdir():
        if f.stat().st_mtime < stale:
            f.unlink(missing_ok=True)
    return done, pending


async def uploads_page(request: Request) -> Response:
    rows = open_db(request).execute("SELECT * FROM uploads ORDER BY created DESC").fetchall()
    shown = [{**dict(r), "fields": json.loads(r["fields"])} for r in rows]
    return page(request, "uploads.html", uploads=shown)


async def fetch_limited(url: str) -> bytes:
    if not url.startswith(("https://", "http://")):
        raise Refused("A URL starts with https:// or http://")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
        async with session.get(url, raise_for_status=True) as r:
            data = bytearray()
            async for chunk in r.content.iter_chunked(65536):
                data += chunk
                if len(data) > MAX_UPLOAD:
                    raise Refused("The file is larger than 16 MiB")
    return bytes(data)


async def check_upload(request: Request) -> Response:
    form = await request.form(max_part_size=MAX_UPLOAD)
    upload = form.get("file")
    url = (form.get("url") or "").strip()
    try:
        if isinstance(upload, UploadFile) and upload.filename:
            data = await upload.read(MAX_UPLOAD + 1)
            if len(data) > MAX_UPLOAD:
                raise Refused("The file is larger than 16 MiB")
            name = upload.filename
        elif url:
            data = await fetch_limited(url)
            name = url
        else:
            raise Refused("Choose a file or give a URL")
        try:
            img = ota.find(data)
        except ValueError as e:
            raise Refused(f"The file was refused: {e}") from None
    except (Refused, aiohttp.ClientError) as e:
        return back("/uploads", str(e))
    body = data[img.start : img.end]
    sha = hashlib.sha512(body).hexdigest()
    _, pending = upload_dirs(request)
    (pending / f"{sha}.ota").write_bytes(body)
    return page(
        request,
        "upload_check.html",
        sha=sha,
        size=len(body),
        image=img,
        trimmed=len(body) != len(data),
        file_name=sources.file_name(name, img.manufacturer, img.image_type, img.version),
        url=url,
    )


async def save_upload(request: Request) -> Response:
    form = await request.form()
    sha = (form.get("sha512") or "").strip()
    done, pending = upload_dirs(request)
    staged = pending / f"{sha}.ota"
    if not SHA512.match(sha) or not staged.exists():
        return back("/uploads", "That check has expired; check the file again")
    body = staged.read_bytes()
    img = ota.find(body)
    try:
        fields = {
            "manufacturer": img.manufacturer,
            "image_type": img.image_type,
            "version": img.version,
            "model_id": (form.get("model_id") or "").strip() or None,
            "manufacturer_names": [
                v.strip() for v in (form.get("manufacturer_names") or "").split(",") if v.strip()
            ]
            or None,
            "min_file_version": optional_int(form.get("min_file_version")),
            "max_file_version": optional_int(form.get("max_file_version")),
            "hardware_min": optional_int(form.get("hardware_min")),
            "hardware_max": optional_int(form.get("hardware_max")),
            "release_notes": (form.get("release_notes") or "").strip() or None,
            "original_url": (form.get("original_url") or "").strip() or None,
        }
    except Refused as e:
        return back("/uploads", str(e))
    name = sources.file_name(
        form.get("file_name") or "", img.manufacturer, img.image_type, img.version
    )
    db = open_db(request)
    staged.replace(done / f"{sha}.ota")
    db.execute(
        "INSERT OR REPLACE INTO uploads (sha512, file_name, fields, author, created)"
        " VALUES (?, ?, ?, ?, ?)",
        (sha, name, json.dumps(fields), request.state.user, dbm.iso(dbm.now())),
    )
    dbm.audit(db, request.state.user, "upload.add", {"sha512": sha, "file_name": name, **fields})
    return back("/uploads", f"Saved {name}; it goes out on the next run")


async def delete_upload(request: Request) -> Response:
    sha = request.path_params["sha"]
    if not SHA512.match(sha):
        return PlainTextResponse("Not a sha512", 400)
    done, _ = upload_dirs(request)
    db = open_db(request)
    row = db.execute("SELECT * FROM uploads WHERE sha512 = ?", (sha,)).fetchone()
    if row is None:
        return back("/uploads", "No such upload")
    db.execute("DELETE FROM uploads WHERE sha512 = ?", (sha,))
    (done / f"{sha}.ota").unlink(missing_ok=True)
    dbm.audit(
        db, request.state.user, "upload.delete", {"sha512": sha, "file_name": row["file_name"]}
    )
    return back("/uploads", f"Deleted {row['file_name']}; it leaves the index on the next run")


async def audit_page(request: Request) -> Response:
    rows = open_db(request).execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    shown = [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]
    return page(request, "audit.html", rows=shown)


def create_app(
    data: Path,
    emails: set[str],
    runs,
    local_user: str | None = None,
    site: Path | None = None,
) -> Starlette:
    """The admin page. `runs` starts and republishes runs, and its `loop`, if it has one, runs
    alongside the app. Run locally, `site` is the published folder, served at /site."""

    @contextlib.asynccontextmanager
    async def lifespan(app):
        scheduler = getattr(runs, "loop", None)
        task = asyncio.create_task(scheduler()) if scheduler else None
        yield
        if task:
            task.cancel()

    local = [Mount("/site", StaticFiles(directory=site, html=True))] if site else []
    app = Starlette(
        lifespan=lifespan,
        routes=local
        + [
            Route("/healthz", healthz),
            Route("/", runs_page),
            Route("/runs/{id:int}", run_detail),
            Route("/runs/{id:int}/publish", confirm_publish),
            Route("/runs/{id:int}/publish", publish_run, methods=["POST"]),
            Route("/publish", publish_now, methods=["POST"]),
            Route("/schedule", save_schedule, methods=["POST"]),
            Route("/sources", sources_page),
            Route("/sources", add_source, methods=["POST"]),
            Route("/sources/{name}", edit_source, methods=["POST"]),
            Route("/images", images),
            Route("/images/{sha}", image_detail),
            Route("/images/{sha}/rule", image_rule, methods=["POST"]),
            Route("/rules", rules_page),
            Route("/rules", add_rule, methods=["POST"]),
            Route("/rules.yaml", rules_yaml),
            Route("/rules/{id}/toggle", toggle_rule, methods=["POST"]),
            Route("/rules/{id}/delete", delete_rule, methods=["POST"]),
            Route("/uploads", uploads_page),
            Route("/uploads/check", check_upload, methods=["POST"]),
            Route("/uploads/save", save_upload, methods=["POST"]),
            Route("/uploads/{sha}/delete", delete_upload, methods=["POST"]),
            Route("/audit", audit_page),
        ],
    )
    app.state.db_path = data / "index.sqlite3"
    app.state.uploads = data / "uploads"
    app.state.runs = runs
    dbm.connect(app.state.db_path).close()
    return Guard(app, {e.strip().lower() for e in emails if e.strip()}, local_user)
