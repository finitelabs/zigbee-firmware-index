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
from firmware_index import kube
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
    bad = admin.post(
        "/sources", data={"name": "x", "type": "index", "config": '{"url": "ftp://x"}'}
    )
    assert "needs" in message(bad)
    bad = admin.post(
        "/sources", data={"name": "x", "type": "zigpy", "config": '{"provider": "nope"}'}
    )
    assert "zigpy" in message(bad)
    bad = admin.post("/sources", data={"name": "x", "type": "index", "config": "[]"})
    assert "Config+must+be+a+JSON+object" in message(bad)
    good = {"name": "vendor", "type": "index", "config": '{"url": "https://v.test/i.json"}'}
    assert "Added+vendor" in message(admin.post("/sources", data={**good, "priority": "7"}))
    admin.post(
        "/sources/vendor",
        data={**good, "priority": "8", "delay_days": "3", "enabled": "1"},
    )
    row = admin.db.execute("SELECT * FROM sources WHERE name = 'vendor'").fetchone()
    assert (row["priority"], row["delay_days"], row["enabled"]) == (8, 3, 1)
    assert audit(admin) == ["source.add", "source.edit"]


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
        data={"action": "set", "hardwareVersionMin": "0x01", "manufacturerName": "A, B"},
    )
    assert admin.post("/images/..%2Fx/rule", data={"action": "hold"}).status_code in (400, 404)
    assert admin.post(f"/images/{'A' * 128}/rule", data={"action": "hold"}).status_code == 400
    assert "at+least+one+field" in message(admin.post(f"/images/{b}/rule", data={"action": "set"}))

    rows = {r["id"]: r for r in admin.db.execute("SELECT * FROM rules")}
    assert set(rows) == {f"hold-{a[:12]}", f"hold-{a[:12]}-2", f"set-{b[:12]}"}
    assert json.loads(rows[f"hold-{a[:12]}"]["match"]) == {"sha512": a}
    assert rows[f"hold-{a[:12]}"]["author"] == ME
    assert json.loads(rows[f"set-{b[:12]}"]["set_fields"]) == {
        "manufacturerName": ["A", "B"],
        "hardwareVersionMin": 1,
    }


def test_rules_are_added_checked_switched_deleted_and_downloaded(admin):
    bad = admin.post("/rules", data={"id": "r1", "action": "hold", "match": "{"})
    assert "not+JSON" in message(bad)
    bad = admin.post("/rules", data={"id": "r1", "action": "hold", "match": '{"colour": 1}'})
    assert "unknown+match+key" in message(bad)
    blank = admin.post("/rules", data={"id": "r1", "action": "set", "set": '{"modelId": "M"}'})
    assert "needs+a+Match" in message(blank)
    listed = admin.post("/rules", data={"id": "r1", "action": "hold", "match": "[]"})
    assert "Match+must+be+a+JSON+object" in message(listed)
    listed = admin.post(
        "/rules", data={"id": "r1", "action": "set", "match": '{"imageType": 1}', "set": "[]"}
    )
    assert "Set+must+be+a+JSON+object" in message(listed)
    assert admin.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
    good = {"id": "r1", "action": "set", "match": '{"imageType": 1}', "set": '{"modelId": "M"}'}
    assert "Added+rule+r1" in message(admin.post("/rules", data=good))
    assert "exists" in message(admin.post("/rules", data=good))

    admin.post("/rules/r1/toggle")
    assert admin.db.execute("SELECT enabled FROM rules").fetchone()[0] == 0
    [rule] = yaml.safe_load(admin.get("/rules.yaml").text)
    assert rule["match"] == {"imageType": 1} and rule["set"] == {"modelId": "M"}
    assert rule["enabled"] is False
    admin.post("/rules/r1/delete")
    assert admin.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
    assert audit(admin) == ["rule.add", "rule.toggle", "rule.delete"]


def test_an_upload_is_checked_cut_to_its_image_and_saved(admin):
    core = ota_file(0x1234, 1, 0x30)
    wrapped = b"NGIS" + bytes(36) + core + b"\xaa" * 8
    checked = admin.post(
        "/uploads/check", files={"file": ("vendor fw.ota", io.BytesIO(wrapped))}
    ).text
    sha = hashlib.sha512(core).hexdigest()
    assert sha in checked and "cut to the OTA image" in checked
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
