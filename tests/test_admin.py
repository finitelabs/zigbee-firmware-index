import asyncio
import hashlib
import io
import json
import sqlite3

import pytest
import yaml
from aiohttp import web
from aiohttp.test_utils import TestServer
from conftest import ota_file
from starlette.testclient import TestClient

from firmware_index import db as dbm
from firmware_index import admin as admin_module
from firmware_index import cli, keys, kube
from firmware_index.admin import create_app

ME = "derek@example.test"
SIGNED_IN = {"x-auth-request-email": ME, "origin": "http://testserver"}


@pytest.fixture
def admin(tmp_path):
    started = []

    async def start(anyway):
        started.append(anyway)
        return "publish-manual-abc12"

    app = create_app(tmp_path, {ME, " "}, start_publish=start)
    client = TestClient(app, headers=SIGNED_IN, follow_redirects=False)
    client.started = started
    client.db = dbm.connect(tmp_path / "index.sqlite3")
    client.data = tmp_path
    return client


def message(response):
    assert response.status_code == 303, response.text
    return response.headers["location"]


def audit(client):
    return [r["action"] for r in client.db.execute("SELECT action FROM audit ORDER BY id")]


def test_the_health_path_needs_no_sign_in(tmp_path):
    client = TestClient(create_app(tmp_path, {ME}))
    assert client.get("/healthz").text == "ok"


def test_only_a_listed_email_gets_in(tmp_path):
    client = TestClient(create_app(tmp_path, {ME}))
    assert client.get("/").status_code == 403
    assert client.get("/", headers={"x-auth-request-email": "x@example.test"}).status_code == 403
    assert (
        client.get("/", headers={"x-auth-request-email": "Derek@Example.test"}).status_code == 200
    )


def test_a_form_from_another_site_is_refused(admin):
    no_origin = {"origin": ""}
    assert admin.post("/publish", headers=no_origin).status_code == 403
    other = {**SIGNED_IN, "origin": "https://evil.test"}
    assert admin.post("/publish", headers=other).status_code == 403
    assert admin.started == []


def test_publish_now_and_anyway_start_a_job_and_are_audited(admin):
    assert "Started+publish-manual-abc12" in message(admin.post("/publish", data={"anyway": "0"}))
    admin.post("/publish", data={"anyway": "1"})
    assert admin.started == [False, True]
    assert audit(admin) == ["publish", "publish"]
    assert "Publish anyway" in admin.get("/").text


def test_sources_are_listed_added_checked_and_edited(admin):
    page = admin.get("/sources").text
    assert "zigpy-ota" in page and "community" in page
    bad = admin.post("/sources", data={"name": "x", "type": "index", "url": "ftp://x"})
    assert "needs+an+https" in message(bad)
    bad = admin.post("/sources", data={"name": "x", "type": "zigpy", "provider": "advanced"})
    assert "zigpy" in message(bad)
    bad = admin.post(
        "/sources", data={"name": "x", "type": "index", "url": "https://v.test", "priority": "x"}
    )
    assert "is+not+a+number" in message(bad)
    good = {"name": "vendor", "type": "index", "url": "https://v.test/i.json"}
    assert "Added+vendor" in message(admin.post("/sources", data={**good, "priority": "7"}))
    admin.post(
        "/sources/vendor",
        data={**good, "priority": "8", "delay_days": "3", "enabled": "1"},
    )
    row = admin.db.execute("SELECT * FROM sources WHERE name = 'vendor'").fetchone()
    assert (row["priority"], row["delay_days"], row["enabled"]) == (8, 3, 1)
    assert json.loads(row["config"]) == {"url": "https://v.test/i.json"}
    beta = {"name": "beta", "type": "zigpy", "provider": "zigpy_ota", "channel": "beta"}
    admin.post("/sources", data=beta)
    row = admin.db.execute("SELECT config FROM sources WHERE name = 'beta'").fetchone()
    assert json.loads(row["config"]) == {"provider": "zigpy_ota", "channel": "beta"}
    community = {"name": "c2", "type": "zigpy", "provider": "z2m", "priority": "0"}
    admin.post("/sources", data=community)
    row = admin.db.execute("SELECT config, priority FROM sources WHERE name = 'c2'").fetchone()
    assert (json.loads(row["config"]), row["priority"]) == ({"provider": "z2m"}, 0)
    page = admin.get("/sources").text
    assert '<option value="z2m" selected>' in page
    sonoff = {"name": "s2", "type": "zigpy", "provider": "sonoff", "channel": "beta"}
    admin.post("/sources", data=sonoff)
    row = admin.db.execute("SELECT config FROM sources WHERE name = 's2'").fetchone()
    assert json.loads(row["config"]) == {"provider": "sonoff"}
    assert audit(admin) == ["source.add", "source.edit", "source.add", "source.add", "source.add"]


def publish_entries(admin, entries):
    admin.db.execute(
        "INSERT INTO published (id, snapshot, sha512, entries, at) VALUES (1, 's', 'x', ?, 't')",
        (json.dumps(entries),),
    )


def entry(sha, mfr, model):
    return {
        "fileName": f"{model}.ota",
        "fileVersion": 0x20,
        "fileSize": 100,
        "url": f"https://ota.example.test/images/{sha[:16]}/{model}.ota",
        "imageType": 1,
        "manufacturerCode": mfr,
        "sha512": sha,
        "otaHeaderString": "x",
        "modelId": model,
        "sources": ["community"],
    }


def test_images_search_and_each_action_makes_a_rule(admin):
    a, b = "a" * 128, "b" * 128
    publish_entries(admin, [entry(a, 0x1234, "Plug"), entry(b, 0x5678, "Bulb")])
    page = admin.get("/images", params={"q": "5678 bulb"}).text
    assert "Bulb.ota" in page and "Plug.ota" not in page
    assert admin.get(f"/images/{a}").status_code == 200
    assert admin.get(f"/images/{'c' * 128}").status_code == 404

    admin.post(f"/images/{a}/rule", data={"action": "hold", "note": "testing on dev"})
    admin.post(f"/images/{a}/rule", data={"action": "hold"})
    admin.post(
        f"/images/{b}/rule",
        data={"action": "set", "s_hardwareVersionMin": "0x01", "s_manufacturerName": "A, B"},
    )
    assert admin.post("/images/..%2Fx/rule", data={"action": "hold"}).status_code in (400, 404)
    assert admin.post(f"/images/{'A' * 128}/rule", data={"action": "hold"}).status_code == 400
    assert "at+least+one+field" in message(admin.post(f"/images/{b}/rule", data={"action": "set"}))

    gone = admin.get(f"/images/{'d' * 128}")
    assert gone.status_code == 404 and "No rule names this file" in gone.text
    admin.post(f"/images/{'d' * 128}/rule", data={"action": "drop", "note": "bricks plugs"})
    gone = admin.get(f"/images/{'d' * 128}").text
    assert f"drop-{'d' * 12}" in gone and "bricks plugs" in gone

    rows = {r["id"]: r for r in admin.db.execute("SELECT * FROM rules")}
    del rows[f"drop-{'d' * 12}"]
    assert set(rows) == {f"hold-{a[:12]}", f"hold-{a[:12]}-2", f"set-{b[:12]}"}
    assert json.loads(rows[f"hold-{a[:12]}"]["match"]) == {"sha512": a}
    assert rows[f"hold-{a[:12]}"]["author"] == ME
    assert json.loads(rows[f"set-{b[:12]}"]["set_fields"]) == {
        "manufacturerName": ["A", "B"],
        "hardwareVersionMin": 1,
    }


def test_rules_are_added_checked_switched_deleted_and_downloaded(admin):
    bad = admin.post("/rules", data={"id": "r1", "action": "hold"})
    assert "at+least+one+thing+to+match" in message(bad)
    bad = admin.post("/rules", data={"id": "r1", "action": "hold", "m_imageType": "one"})
    assert "is+not+a+number" in message(bad)
    bad = admin.post("/rules", data={"id": "r1", "action": "hold", "m_sha512": "abc"})
    assert "128+hex+digits" in message(bad)
    bad = admin.post("/rules", data={"id": "r1", "action": "set", "m_imageType": "1"})
    assert "at+least+one+field+to+set" in message(bad)
    assert admin.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
    good = {"id": "r1", "action": "set", "m_imageType": "1", "s_modelId": "M"}
    assert "Added+rule+r1" in message(admin.post("/rules", data=good))
    assert "exists" in message(admin.post("/rules", data=good))
    ranged = {
        "id": "r2",
        "action": "hold",
        "m_source": "community",
        "m_manufacturerCode": "0x1234",
        "m_versionMin": "0x10",
        "m_versionMax": "0x20",
        "m_url": "*/Vendor/*",
        "s_modelId": "ignored for a hold",
    }
    admin.post("/rules", data=ranged)
    one = {"id": "r3", "action": "drop", "m_versionMin": "0x10", "m_versionMax": "0x10"}
    admin.post("/rules", data=one)
    rows = {r["id"]: r for r in admin.db.execute("SELECT * FROM rules")}
    assert json.loads(rows["r2"]["match"]) == {
        "source": "community",
        "manufacturerCode": 0x1234,
        "fileVersion": {"min": 0x10, "max": 0x20},
        "url": "*/Vendor/*",
    }
    assert json.loads(rows["r2"]["set_fields"]) == {}
    assert json.loads(rows["r3"]["match"]) == {"fileVersion": 0x10}
    page = admin.get("/rules").text
    assert "0x1234" in page and "0x00000010 to 0x00000020" in page
    admin.post("/rules/r2/delete")
    admin.post("/rules/r3/delete")

    admin.post("/rules/r1/toggle")
    assert admin.db.execute("SELECT enabled FROM rules").fetchone()[0] == 0
    [rule] = yaml.safe_load(admin.get("/rules.yaml").text)
    assert rule["match"] == {"imageType": 1} and rule["set"] == {"modelId": "M"}
    assert rule["enabled"] is False
    admin.post("/rules/r1/delete")
    assert admin.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
    assert audit(admin) == [
        "rule.add",
        "rule.add",
        "rule.add",
        "rule.delete",
        "rule.delete",
        "rule.toggle",
        "rule.delete",
    ]


def test_an_upload_is_checked_cut_to_its_image_and_saved(admin):
    core = ota_file(0x1234, 1, 0x30)
    wrapped = b"NGIS" + bytes(36) + core + b"\xaa" * 8
    checked = admin.post(
        "/uploads/check", files={"file": ("vendor fw.ota", io.BytesIO(wrapped))}
    ).text
    sha = hashlib.sha512(core).hexdigest()
    assert sha in checked and "cut to its OTA image" in checked
    assert "1234-0001-00000030.ota" in checked

    saved = admin.post(
        "/uploads/save",
        data={"sha512": sha, "file_name": "vendor-fw.ota", "model_id": "M", "hardware_min": "0x2"},
    )
    assert "Saved+vendor-fw.ota" in message(saved)
    assert (admin.data / "uploads" / f"{sha}.ota").read_bytes() == core
    row = admin.db.execute("SELECT * FROM uploads").fetchone()
    fields = json.loads(row["fields"])
    assert (fields["manufacturer"], fields["version"], fields["model_id"]) == (0x1234, 0x30, "M")
    assert fields["hardware_min"] == 2 and row["author"] == ME

    admin.post(f"/uploads/{sha}/delete")
    assert not (admin.data / "uploads" / f"{sha}.ota").exists()
    assert audit(admin) == ["upload.add", "upload.delete"]


def test_an_upload_that_is_no_firmware_is_refused(admin):
    refused = admin.post("/uploads/check", files={"file": ("x.bin", io.BytesIO(b"no" * 100))})
    assert "no+OTA+header" in message(refused)
    stale = admin.post("/uploads/save", data={"sha512": "a" * 128})
    assert "expired" in message(stale)


def test_dump_writes_a_database_that_opens(tmp_path):
    db = dbm.connect(tmp_path / "index.sqlite3")
    dbm.audit(db, ME, "x", {})
    out = io.BytesIO()
    dbm.dump(tmp_path / "index.sqlite3", out)
    copy = tmp_path / "copy.sqlite3"
    copy.write_bytes(out.getvalue())
    assert sqlite3.connect(copy).execute("SELECT who FROM audit").fetchone() == (ME,)


def test_a_job_from_the_cronjob_carries_its_template_and_anyway():
    cronjob = {
        "metadata": {"name": "publish", "uid": "u-1"},
        "spec": {
            "jobTemplate": {
                "metadata": {"labels": {"app": "firmware"}},
                "spec": {
                    "template": {"spec": {"containers": [{"name": "p", "args": ["publish"]}]}}
                },
            }
        },
    }
    job = kube.job_from(json.loads(json.dumps(cronjob)), anyway=False)
    assert job["metadata"]["generateName"] == "publish-manual-"
    assert job["metadata"]["ownerReferences"][0]["uid"] == "u-1"
    assert job["metadata"]["labels"] == {"app": "firmware"}
    assert job["spec"]["template"]["spec"]["containers"][0]["args"] == ["publish"]
    job = kube.job_from(json.loads(json.dumps(cronjob)), anyway=True)
    assert job["spec"]["template"]["spec"]["containers"][0]["args"] == ["publish", "--anyway"]
    del cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["args"]
    job = kube.job_from(cronjob, anyway=True)
    assert job["spec"]["template"]["spec"]["containers"][0]["args"] == ["publish", "--anyway"]


def test_a_url_upload_reads_the_whole_file_however_it_arrives():
    body = ota_file(0x1234, 1, 0x30, payload=bytes(range(256)) * 1200)

    async def go():
        async def chunked(request):
            response = web.StreamResponse()
            await response.prepare(request)
            for i in range(0, len(body), 4096):
                await response.write(body[i : i + 4096])
                await asyncio.sleep(0)
            return response

        app = web.Application()
        app.router.add_get("/fw.ota", chunked)
        async with TestServer(app) as server:
            return await admin_module.fetch_limited(str(server.make_url("/fw.ota")))

    assert asyncio.run(go()) == body


def test_run_locally_the_local_user_needs_no_sign_in_and_the_site_is_served(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.json").write_text("[]\n")
    started = []

    async def start(anyway):
        started.append(anyway)
        return "a local run"

    app = create_app(tmp_path, {"local@localhost"}, start, "local@localhost", site)
    assert TestClient(app).get("/", headers={"host": "rebound.example.test"}).status_code == 403
    client = TestClient(app, base_url="http://localhost:8080", follow_redirects=False)
    assert "local@localhost" in client.get("/").text
    assert client.get("/", headers={"x-auth-request-email": "x@example.test"}).status_code == 200
    assert client.get("/site/index.json").text == "[]\n"
    assert client.post("/publish", data={"anyway": "0"}).status_code == 403
    done = client.post(
        "/publish", data={"anyway": "0"}, headers={"origin": "http://localhost:8080"}
    )
    assert "Started+a+local+run" in done.headers["location"] and started == [False]


def test_the_site_is_served_only_when_run_locally(admin):
    assert admin.get("/site/index.json").status_code == 404


def test_local_settings_make_one_key_and_publish_to_the_folder(tmp_path):
    data, first = cli.local_settings(tmp_path, "http://127.0.0.1:8080/site/", False)
    _, again = cli.local_settings(tmp_path, "http://127.0.0.1:8080/site", True)
    assert data == tmp_path / "data"
    assert keys.public_hex(first.key) == keys.public_hex(again.key)
    assert first.public_url == "http://127.0.0.1:8080/site" and again.anyway
    first.store.put("x/y.json", b"{}", "application/json", "")
    assert (tmp_path / "site" / "x" / "y.json").read_bytes() == b"{}"
