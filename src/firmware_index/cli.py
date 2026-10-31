"""The firmware-index command."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import aiohttp

from firmware_index import db as dbm
from firmware_index import keys, notify, publish
from firmware_index.store import DirStore, R2Store

EXIT = {publish.OK: 0, publish.FAILED: 1, publish.BRAKE: 2}


def keygen(args: argparse.Namespace) -> int:
    try:
        public = keys.generate(args.path)
    except FileExistsError:
        print(f"error: {args.path} exists; a key is never written over", file=sys.stderr)
        return 1
    print(public)
    return 0


def env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"error: {name} is not set")
    return value


def run_publish(args: argparse.Namespace) -> int:
    if args.dry_run:
        root = args.dry_run
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        key_path = data / "dry-run.pem"
        if not key_path.exists():
            keys.generate(key_path)
        store = DirStore(root / "site")
        webhook = None
        base = os.environ.get("PUBLIC_URL", (root / "site").resolve().as_uri())
    else:
        data = data_dir()
        key_path = Path(env("SIGNING_KEY_PATH"))
        store = R2Store(
            env("R2_ENDPOINT"),
            env("R2_BUCKET"),
            env("R2_ACCESS_KEY_ID"),
            env("R2_SECRET_ACCESS_KEY"),
        )
        webhook = os.environ.get("DISCORD_WEBHOOK_URL")
        base = os.environ.get("PUBLIC_URL", "https://ota.finitelabs.com")

    settings = publish.Settings(
        public_url=base.rstrip("/"), key=keys.load(key_path), store=store, anyway=args.anyway
    )
    db = dbm.connect(data / "index.sqlite3")

    async def go():
        async with aiohttp.ClientSession() as session:
            report = await publish.run(db, settings, publish.HttpFetcher(session), data / "uploads")
        await notify.post(webhook, report)
        return report

    report = asyncio.run(go())
    print(json.dumps({"status": report.status, "counts": report.counts, "alerts": report.alerts}))
    return EXIT[report.status]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firmware-index")
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser(
        "keygen",
        help="write a new Ed25519 signing key and print its public key in hex",
    )
    p.add_argument("path", type=Path, help="where to write the private key (PEM)")
    p.set_defaults(run=keygen)

    p = commands.add_parser("publish", help="run once: check the sources and publish")
    p.add_argument(
        "--anyway", action="store_true", help="publish even if the brake would hold the index"
    )
    p.add_argument(
        "--dry-run",
        type=Path,
        metavar="DIR",
        help="publish to DIR/site with its own database and key in DIR/data",
    )
    p.set_defaults(run=run_publish)

    p = commands.add_parser("serve", help="the admin page")
    p.set_defaults(run=serve)

    p = commands.add_parser("dump", help="write a consistent copy of the database to stdout")
    p.set_defaults(run=dump)

    p = commands.add_parser("check", help="check the public site as a reader sees it")
    p.add_argument("url", help="the site, for example https://ota.finitelabs.com")
    p.set_defaults(run=run_check)

    args = parser.parse_args(argv)
    return args.run(args)


def data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data"))


def serve(args: argparse.Namespace) -> int:
    import uvicorn

    from firmware_index.admin import create_app

    emails = set(env("ADMIN_EMAILS").split(","))
    app = create_app(data_dir(), emails)
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
        proxy_headers=False,
    )
    return 0


def dump(args: argparse.Namespace) -> int:
    dbm.dump(data_dir() / "index.sqlite3", sys.stdout.buffer)
    return 0


def run_check(args: argparse.Namespace) -> int:
    from firmware_index import check

    async def go():
        async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
            return await check.problems(
                args.url.rstrip("/"),
                publish.HttpFetcher(session),
                dbm.now(),
                os.environ.get("SIGNING_KEY_PUB") or None,
            )

    found = asyncio.run(go())
    for p in found:
        print(f"error: {p}", file=sys.stderr)
    if not found:
        print(f"{args.url}: ok")
    return 1 if found else 0
