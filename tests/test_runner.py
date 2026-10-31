import asyncio
import datetime

import pytest

from firmware_index import db as dbm
from firmware_index import runner

UTC = datetime.UTC


def at(hour, minute=0, day=31):
    return datetime.datetime(2026, 10, day, hour, minute, tzinfo=UTC)


def test_a_run_is_due_once_a_day_at_or_after_its_time():
    assert not runner.due(True, "04:00", None, at(3, 59))
    assert runner.due(True, "04:00", None, at(4))
    assert runner.due(True, "04:00", "2026-10-30", at(15))
    assert not runner.due(True, "04:00", "2026-10-31", at(15))
    assert not runner.due(False, "04:00", None, at(15))


def test_the_next_run_is_today_or_tomorrow():
    assert runner.next_run("04:00", at(3)) == at(4)
    assert runner.next_run("04:00", at(4)) == at(4, day=1).replace(month=11)
    assert runner.next_run("23:30", at(12)) == at(23, 30)


@pytest.fixture
def runs(tmp_path, monkeypatch):
    started = []

    async def fake_publish(data, settings, webhook):
        started.append(settings)
        await asyncio.sleep(0.01)

    monkeypatch.setattr(runner, "publish_once", fake_publish)
    dbm.connect(tmp_path / "index.sqlite3").close()
    r = runner.Runner(tmp_path, lambda anyway: {"anyway": anyway}, None)
    r.started = started
    r.path = tmp_path / "index.sqlite3"
    return r


def test_a_tick_starts_the_day_s_run_once(runs):
    async def go():
        assert not await runs.tick(at(3))
        assert await runs.tick(at(4, 1))
        await runs.task
        assert not await runs.tick(at(9))
        assert await runs.tick(at(4, 1, day=1).replace(month=11))
        await runs.task

    asyncio.run(go())
    assert runs.started == [{"anyway": False}, {"anyway": False}]


def test_a_switched_off_schedule_never_starts_a_run(runs):
    db = dbm.connect(runs.path)
    dbm.set_setting(db, "schedule_on", "0")
    db.close()
    assert not asyncio.run(runs.tick(at(12)))
    assert runs.started == []


def test_one_run_at_a_time(runs):
    async def go():
        assert await runs.start(True) == "a run"
        with pytest.raises(RuntimeError, match="already going"):
            await runs.start(False)
        assert not await runs.tick(at(12))
        await runs.task

    asyncio.run(go())
    assert runs.started == [{"anyway": True}]
