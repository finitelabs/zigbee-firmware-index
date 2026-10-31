import asyncio
import datetime

import pytest

from firmware_index import db as dbm
from firmware_index import publish, runner

UTC = datetime.UTC


def at(hour, minute=0, day=31):
    return datetime.datetime(2026, 10, day, hour, minute, tzinfo=UTC)


def test_a_run_is_due_once_a_day_at_or_after_its_time():
    assert not runner.due(True, "04:00", None, at(3, 59))
    assert runner.due(True, "04:00", None, at(4))
    assert runner.due(True, "04:00", "2026-10-30", at(15))
    assert not runner.due(True, "04:00", "2026-10-31", at(15))
    assert not runner.due(False, "04:00", None, at(15))


def test_the_next_run_is_due_now_today_or_tomorrow():
    assert runner.next_run("04:00", at(3), None) == at(4)
    assert runner.next_run("04:00", at(9), None) == at(9)
    assert runner.next_run("04:00", at(9), "2026-10-31") == at(4, day=1).replace(month=11)
    # Today's run done at 04:00 and the time then moved to 05:00: the next is tomorrow's.
    assert runner.next_run("05:00", at(4, 30), "2026-10-31") == at(5, day=1).replace(month=11)
    assert runner.next_run("23:30", at(12), "2026-10-30") == at(23, 30)


@pytest.fixture
def runs(tmp_path, monkeypatch):
    started = []

    async def fake_publish(data, settings, webhook):
        started.append(settings)
        await asyncio.sleep(0.01)
        return publish.Report(started="t")

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


def test_a_scheduled_run_cut_short_is_caught_up(runs, monkeypatch):
    async def slow(data, settings, webhook):
        await asyncio.sleep(30)

    monkeypatch.setattr(runner, "publish_once", slow)

    async def go():
        assert await runs.tick(at(4, 1))
        await asyncio.sleep(0)
        runs.task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await runs.task
        db = dbm.connect(runs.path)
        assert dbm.get_setting(db, "schedule_last") is None
        db.close()
        assert await runs.tick(at(4, 2))
        runs.task.cancel()

    asyncio.run(go())


def test_a_finished_scheduled_run_marks_its_day(runs):
    async def go():
        await runs.tick(at(4, 1))
        await runs.task

    asyncio.run(go())
    db = dbm.connect(runs.path)
    assert dbm.get_setting(db, "schedule_last") == "2026-10-31"


def test_a_discord_post_that_times_out_still_marks_the_day(tmp_path, monkeypatch):
    from firmware_index import notify, publish

    async def fake_run(db, settings, fetcher, uploads):
        report = publish.Report(started="2026-10-31T04:01:00Z")
        report.alerts.append("source x failed")
        return report

    class Hangs:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            raise TimeoutError()

    monkeypatch.setattr(publish, "run", fake_run)
    monkeypatch.setattr(notify.aiohttp, "ClientSession", Hangs)
    dbm.connect(tmp_path / "index.sqlite3").close()
    r = runner.Runner(tmp_path, lambda anyway: None, "https://discord.test/hook")

    async def go():
        assert await r.tick(at(4, 1))
        await r.task
        assert not await r.tick(at(4, 2))

    asyncio.run(go())
    db = dbm.connect(tmp_path / "index.sqlite3")
    assert dbm.get_setting(db, "schedule_last") == "2026-10-31"


def test_a_republish_counts_as_the_running_run(runs, monkeypatch):
    async def slow(db, settings, run_id):
        await asyncio.sleep(0.05)
        return publish.Report(started="t")

    monkeypatch.setattr(publish, "republish", slow)

    async def go():
        job = asyncio.create_task(runs.republish(1))
        await asyncio.sleep(0.01)
        assert runs.running
        assert not await runs.tick(at(4, 1))
        with pytest.raises(RuntimeError, match="already going"):
            await runs.start(False)
        await job

    asyncio.run(go())
    assert runs.started == []


def test_a_scheduled_run_the_lock_refused_leaves_its_day_open(runs, monkeypatch):
    async def locked(data, settings, webhook):
        report = publish.Report(started="t", status=publish.FAILED)
        report.alerts.append(publish.LOCKED)
        return report

    monkeypatch.setattr(runner, "publish_once", locked)

    async def go():
        assert await runs.tick(at(4, 1))
        await runs.task
        assert await runs.tick(at(4, 2))
        await runs.task

    asyncio.run(go())


def test_no_run_starts_while_another_holds_the_lock(runs):
    db = dbm.connect(runs.path)
    assert dbm.take_lock(db, "cli", at(4))
    db.close()

    async def go():
        for minute in range(1, 6):
            assert not await runs.tick(at(4, minute))
        assert await runs.tick(at(10, 1))
        await runs.task

    asyncio.run(go())
    assert runs.started == [{"anyway": False}]


def test_a_rollback_pauses_scheduled_runs_from_inside_its_task(runs, monkeypatch):
    results = iter([publish.OK, publish.FAILED, publish.OK])

    async def republish(db, settings, run_id):
        return publish.Report(started="t", status=next(results))

    monkeypatch.setattr(publish, "republish", republish)

    async def go():
        await runs.republish(1, pause=True)
        with pytest.raises(RuntimeError):
            await runs.republish(2, pause=True)
        await runs.republish(3)

    asyncio.run(go())
    db = dbm.connect(runs.path)
    assert dbm.get_setting(db, "paused_for") == "1"
    db.close()


def test_a_paused_schedule_starts_nothing_until_resumed(runs):
    db = dbm.connect(runs.path)
    dbm.set_setting(db, "paused_for", "4")
    db.close()
    assert not asyncio.run(runs.tick(at(12)))
    db = dbm.connect(runs.path)
    dbm.set_setting(db, "paused_for", "")
    db.close()

    async def go():
        assert await runs.tick(at(12))
        await runs.task

    asyncio.run(go())
