"""The admin page: runs, sources, images, rules, uploads and the audit log."""

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
from firmware_index import kube, ota, rules, sources

EMAIL_HEADER = "x-auth-request-email"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_UPLOAD = 16 * 1024 * 1024
LIST_LIMIT = 200
PENDING_SECONDS = 24 * 3600
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent / "templates")
TEMPLATES.env.filters["hex4"] = lambda n: "" if n is None else f"0x{n:04X}"
TEMPLATES.env.filters["hex8"] = lambda n: "" if n is None else f"0x{n:08X}"


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


def page(request: Request, name: str, **context) -> Response:
    context.setdefault("message", request.query_params.get("message"))
    return TEMPLATES.TemplateResponse(request, name, {"user": request.state.user, **context})


def back(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"{path}?{urlencode({'message': message})}", status_code=303)


def optional_int(value: str | None) -> int | None:
    value = (value or "").strip()
    return int(value, 0) if value else None


def parse_json(value: str, what: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError as e:
        raise Refused(f"{what} is not JSON: {e.msg}") from None
    if not isinstance(parsed, dict):
        raise Refused(f"{what} must be a JSON object")
    return parsed


async def healthz(request: Request) -> Response:
    dbm.connect(request.app.state.db_path).close()
    return PlainTextResponse("ok")


async def runs(request: Request) -> Response:
    db = open_db(request)
    rows = db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 30").fetchall()
    shown = [{**dict(r), "report": json.loads(r["report"] or "{}")} for r in rows]
    published = db.execute("SELECT snapshot, at FROM published WHERE id = 1").fetchone()
    return page(request, "runs.html", runs=shown, published=published)


async def run_detail(request: Request) -> Response:
    row = (
        open_db(request)
        .execute("SELECT * FROM runs WHERE id = ?", (request.path_params["id"],))
        .fetchone()
    )
    if row is None:
        return PlainTextResponse("No such run", 404)
    return page(request, "run.html", run=dict(row), report=json.loads(row["report"] or "{}"))


async def publish_now(request: Request) -> Response:
    form = await request.form()
    anyway = form.get("anyway") == "1"
    try:
        job = await request.app.state.start_publish(anyway)
    except Exception as e:
        return back("/", f"Could not start a run: {type(e).__name__}: {e}")
    dbm.audit(open_db(request), request.state.user, "publish", {"job": job, "anyway": anyway})
    return back("/", f"Started {job}")


async def sources_page(request: Request) -> Response:
    rows = open_db(request).execute("SELECT * FROM sources ORDER BY priority").fetchall()
    return page(
        request,
        "sources.html",
        sources=[
            {**dict(r), "candidates": len(json.loads(r["last_candidates"] or "[]"))} for r in rows
        ],
        types=[sources.INDEX, sources.ZIGPY, sources.UPLOAD],
    )


def source_fields(form) -> dict:
    kind = form.get("type")
    config = parse_json(form.get("config", ""), "Config")
    if kind == sources.INDEX and not str(config.get("url", "")).startswith("https://"):
        raise Refused('An index source needs {"url": "https://..."}')
    if kind == sources.ZIGPY:
        import zigpy.ota.providers

        if config.get("provider") not in zigpy.ota.providers.OTA_PROVIDER_TYPES:
            raise Refused('A zigpy source needs {"provider": ...} naming one of zigpy\'s providers')
    if kind not in (sources.INDEX, sources.ZIGPY, sources.UPLOAD):
        raise Refused(f"Unknown type {kind!r}")
    return {
        "type": kind,
        "config": json.dumps(config),
        "priority": int(form.get("priority", "10")),
        "delay_days": int(form.get("delay_days", "0")),
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
    row = open_db(request).execute("SELECT entries FROM published WHERE id = 1").fetchone()
    entries = [e for e in json.loads(row["entries"]) if e["sha512"] == sha] if row else []
    if not entries:
        return PlainTextResponse("No such image in the published index", 404)
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


async def image_rule(request: Request) -> Response:
    sha = request.path_params["sha"]
    if not SHA512.match(sha):
        return PlainTextResponse("Not a sha512", 400)
    form = await request.form()
    action = form.get("action")
    fields = {}
    try:
        if action == rules.SET:
            for name in rules.SETTABLE:
                value = (form.get(name) or "").strip()
                if not value:
                    continue
                if name == "manufacturerName":
                    fields[name] = [v.strip() for v in value.split(",") if v.strip()]
                elif name in ("releaseNotes", "modelId", "otaHeaderString"):
                    fields[name] = value
                else:
                    fields[name] = int(value, 0)
            if not fields:
                raise Refused("Give at least one field to set")
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
    rows = open_db(request).execute("SELECT * FROM rules ORDER BY created, id").fetchall()
    shown = [
        {**dict(r), "match": json.loads(r["match"]), "set": json.loads(r["set_fields"])}
        for r in rows
    ]
    return page(request, "rules.html", rules=shown, actions=[rules.DROP, rules.HOLD, rules.SET])


async def add_rule(request: Request) -> Response:
    form = await request.form()
    db = open_db(request)
    try:
        rid = (form.get("id") or "").strip()
        if not RULE_ID.match(rid):
            raise Refused("An id is letters, digits, dots, dashes and underscores")
        if db.execute("SELECT 1 FROM rules WHERE id = ?", (rid,)).fetchone():
            raise Refused(f"A rule {rid} exists")
        match = parse_json(form.get("match", ""), "Match")
        if not match:
            raise Refused('A rule needs a Match; for every file, say {"url": "*"}')
        rule = rules.Rule(
            id=rid,
            action=form.get("action"),
            match=match,
            set=parse_json(form.get("set", ""), "Set"),
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
    except ValueError as e:
        return back("/uploads", f"A number did not parse: {e}")
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
    return page(request, "audit.html", rows=rows)


def create_app(
    data: Path,
    emails: set[str],
    start_publish=kube.start_publish,
    local_user: str | None = None,
    site: Path | None = None,
) -> Starlette:
    """The admin page. Run locally, `site` is the published folder, served at /site."""
    local = [Mount("/site", StaticFiles(directory=site, html=True))] if site else []
    app = Starlette(
        routes=local
        + [
            Route("/healthz", healthz),
            Route("/", runs),
            Route("/runs/{id:int}", run_detail),
            Route("/publish", publish_now, methods=["POST"]),
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
        ]
    )
    app.state.db_path = data / "index.sqlite3"
    app.state.uploads = data / "uploads"
    app.state.start_publish = start_publish
    dbm.connect(app.state.db_path).close()
    return Guard(app, {e.strip().lower() for e in emails if e.strip()}, local_user)
