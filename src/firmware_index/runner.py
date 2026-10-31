"""Runs inside serve: Publish now, and the daily schedule."""

import asyncio
import datetime
import logging
from collections.abc import Callable
from pathlib import Path

import aiohttp

from firmware_index import db as dbm
from firmware_index import notify, publish

LOG = logging.getLogger(__name__)
DEFAULT_AT = "04:00"
TICK_SECONDS = 60


async def publish_once(data: Path, settings: publish.Settings, webhook: str | None):
    db = dbm.connect(data / "index.sqlite3")
    try:
        async with aiohttp.ClientSession() as session:
            report = await publish.run(db, settings, publish.HttpFetcher(session), data / "uploads")
    finally:
        db.close()
    await notify.post(webhook, report)
    return report


def schedule(db) -> tuple[bool, str]:
    on = dbm.get_setting(db, "schedule_on", "1") == "1"
    return on, dbm.get_setting(db, "schedule_at", DEFAULT_AT)


def today_at(at: str, now: datetime.datetime) -> datetime.datetime:
    hour, minute = (int(p) for p in at.split(":"))
    return now.replace(hour=hour, minute=minute, second=0, microsecond=0)


def next_run(at: str, now: datetime.datetime) -> datetime.datetime:
    t = today_at(at, now)
    return t if t > now else t + datetime.timedelta(days=1)


def due(on: bool, at: str, last_day: str | None, now: datetime.datetime) -> bool:
    """Once a day, at or after its time; a restart after the time catches up the same day."""
    return on and now >= today_at(at, now) and last_day != now.date().isoformat()


class Runner:
    def __init__(
        self, data: Path, settings_for: Callable[[bool], publish.Settings], webhook: str | None
    ):
        self.data = data
        self.settings_for = settings_for
        self.webhook = webhook
        self.task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    async def start(self, anyway: bool) -> str:
        if self.running:
            raise RuntimeError("a run is already going")
        self.task = asyncio.create_task(
            publish_once(self.data, self.settings_for(anyway), self.webhook)
        )
        return "a run"

    async def tick(self, now: datetime.datetime) -> bool:
        db = dbm.connect(self.data / "index.sqlite3")
        try:
            on, at = schedule(db)
            if self.running or not due(on, at, dbm.get_setting(db, "schedule_last"), now):
                return False
            dbm.set_setting(db, "schedule_last", now.date().isoformat())
        finally:
            db.close()
        await self.start(False)
        return True

    async def loop(self) -> None:
        while True:
            try:
                await self.tick(dbm.now())
            except Exception:
                LOG.exception("the scheduled run could not start")
            await asyncio.sleep(TICK_SECONDS)
