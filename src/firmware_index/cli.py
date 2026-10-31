"""The firmware-index command."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import aiohttp

from firmware_index import db as dbm
from firmware_index import keys, publish
from firmware_index.runner import Runner, publish_once
from firmware_index.store import DirStore, R2Store

EXIT = {publish.OK: 0, publish.FAILED: 1, publish.BRAKE: 2}
LOCAL_USER = "local@localhost"
LOCAL_PORT = 8080


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


def local_settings(root: Path, base: str, anyway: bool) -> tuple[Path, publish.Settings]:
    """Run locally: the store is the folder root/site, and root/data holds the database and a
    signing key made on first use."""
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    key_path = data / "local.pem"
    if not key_path.exists():
        keys.generate(key_path)
    settings = publish.Settings(
        public_url=base.rstrip("/"),
        key=keys.load(key_path),
        store=DirStore(root / "site"),
        anyway=anyway,
    )
    return data, settings


def run_publish(args: argparse.Namespace) -> int:
    if args.local:
        base = os.environ.get("PUBLIC_URL", f"http://127.0.0.1:{LOCAL_PORT}/site")
        data, settings = local_settings(args.local, base, args.anyway)
        webhook = None
    else:
        data, settings, webhook = data_dir(), r2_settings(args.anyway), discord()

    report = asyncio.run(publish_once(data, settings, webhook))
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
        "--local",
        type=Path,
        metavar="DIR",
        help="publish to the folder DIR/site, with its own database and key in DIR/data",
    )
    p.set_defaults(run=run_publish)

    p = commands.add_parser("serve", help="the admin page")
    p.add_argument(
        "--local",
        type=Path,
        metavar="DIR",
        help="run on this computer: 127.0.0.1 only, no sign-in, runs publish to DIR",
    )
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


def discord() -> str | None:
    return os.environ.get("DISCORD_WEBHOOK_URL")


def r2_settings(anyway: bool) -> publish.Settings:
    return publish.Settings(
        public_url=os.environ.get("PUBLIC_URL", "https://ota.finitelabs.com").rstrip("/"),
        key=keys.load(Path(env("SIGNING_KEY_PATH"))),
        store=R2Store(
            env("R2_ENDPOINT"),
            env("R2_BUCKET"),
            env("R2_ACCESS_KEY_ID"),
            env("R2_SECRET_ACCESS_KEY"),
        ),
        anyway=anyway,
    )


def serve(args: argparse.Namespace) -> int:
    import uvicorn

    from firmware_index.admin import create_app

    if args.local:
        port = int(os.environ.get("PORT", LOCAL_PORT))
        base = f"http://127.0.0.1:{port}/site"
        root = args.local
        (root / "site").mkdir(parents=True, exist_ok=True)
        data, _ = local_settings(root, base, False)
        runs = Runner(data, lambda anyway: local_settings(root, base, anyway)[1], None)
        app = create_app(
            data,
            {LOCAL_USER},
            runs.start,
            local_user=LOCAL_USER,
            site=root / "site",
            scheduler=runs.loop,
        )
        print(f"The admin page is at http://127.0.0.1:{port}/ and the site at {base}/")
        uvicorn.run(app, host="127.0.0.1", port=port)
        return 0

    r2_settings(False)  # fail at start, not at the first run, when a setting is missing
    runs = Runner(data_dir(), r2_settings, discord())
    emails = set(env("ADMIN_EMAILS").split(","))
    app = create_app(data_dir(), emails, runs.start, scheduler=runs.loop)
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
        async with aiohttp.ClientSession() as session:
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
