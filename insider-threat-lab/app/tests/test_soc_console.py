import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import banking_app  # noqa: E402
from soc import detections, events, incidents  # noqa: E402



def build_log():
    lines = []
    for i in range(6):  # 6 failed sign-ins on jdoe within minutes -> one burst
        lines.append(f"2026-01-18 19:1{i}:00,100 - INFO - LOGIN_FAILED: Failed login attempt for jdoe - USER:anonymous - IP:10.0.0.9")
    lines.append("2026-01-18 21:00:00,100 - INFO - LOGIN_FAILED: Failed login attempt for admin - USER:anonymous - IP:10.0.0.9")
    for i in range(5):  # admin views 5 x 50 = 250 records in one hour
        lines.append(f"2026-01-19 19:2{i}:00,100 - INFO - DATABASE_QUERY: Query: SELECT customers | Rows: 50 | Time: 0.01s - USER:admin - IP:172.18.0.1")
    lines.append('2026-01-19 19:30:00,100 - INFO - SEARCH_QUERY: Search: "a" | Results: 294 | Time: 0.01s - USER:jdoe - IP:172.18.0.1')
    lines.append("2026-10-23 13:43:26,979 - INFO - MOBILE_RISK_ASSESSMENT: Assessment: abc-123 | Sample: kd-x | Channel: analyst-ui | Verdict: flag_for_review | Score: 0.95 | Threshold: 0.5 | Model: bwm - USER:analyst - IP:172.21.0.1")
    lines.append("2026-10-23 13:44:00,000 - INFO - MOBILE_RISK_ASSESSMENT: Assessment: def-456 | Sample: kd-y | Channel: analyst-ui | Verdict: not_flagged | Score: 0.01 | Threshold: 0.5 | Model: bwm - USER:analyst - IP:172.21.0.1")
    for i in range(3):
        lines.append(f"2026-10-23 14:0{i}:00,000 - WARNING - API_AUTH_FAILED: /api/v1/mobile - USER:unknown-client - IP:172.21.0.5")
    lines.append("2026-10-23 14:10:00,000 - INFO - werkzeug noise without the format")
    return "\n".join(lines) + "\n"


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    log = tmp_path / "banking_app.log"
    log.write_text(build_log())
    monkeypatch.setenv("APP_LOG_FILE", str(log))
    monkeypatch.setenv("MOBILE_RISK_DB", str(tmp_path / "bw.db"))


@pytest.fixture
def ui():
    with banking_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["username"] = "analyst"
        yield c


def test_parse_events_plain_names():
    evs = events.read_events()
    assert len(evs) == 18  # malformed line skipped
    assert {e["name"] for e in evs} >= {"Failed sign-in", "Viewed customer list", "Checked an Android app"}
    db = next(e for e in evs if e["code"] == "DATABASE_QUERY")
    assert db["records"] == 50 and db["category"] == "data"


def test_detection_rules():
    all_found = list(detections.run_all(events.read_events()))
    found = {f["rule"]: f for f in all_found}
    assert set(found) == {"failed_logins", "bulk_data", "broad_search", "risky_app", "api_abuse"}
    # admin's 250 records and jdoe's single 294-record search are both above the 200/hour alert level
    assert sorted((f["entity"], f["records"]) for f in all_found if f["rule"] == "bulk_data") == [("admin", 250), ("jdoe", 294)]
    assert found["failed_logins"]["event_count"] == 6 and found["failed_logins"]["entity"] == "jdoe"
    assert "insider" in found["bulk_data"]["summary"]
    assert found["risky_app"]["severity"] == "high" and found["risky_app"]["assessment_id"] == "abc-123"
    assert all(f["evidence"] for f in found.values())


def test_sync_is_idempotent_and_keeps_analyst_changes(ui):
    assert ui.post("/api/soc/sync", json={}).get_json()["new"] == 6
    first = ui.get("/api/soc/incidents?status=new").get_json()[0]
    ui.patch(f"/api/soc/incidents/{first['id']}", json={"status": "investigating", "assignee": "jdoe"})
    assert ui.post("/api/soc/sync", json={}).get_json() == {"new": 0, "updated": 0}
    again = ui.get(f"/api/soc/incidents/{first['id']}").get_json()
    assert again["status"] == "investigating" and again["assignee"] == "jdoe"


def test_incident_workflow_tags_notes_timeline(ui):
    ui.post("/api/soc/sync", json={})
    iid = ui.get("/api/soc/incidents").get_json()[0]["id"]
    r = ui.patch(f"/api/soc/incidents/{iid}", json={"add_tag": "Escalate Now!", "assignee": "Stacey-Lee"}).get_json()
    assert "escalate-now" in r["incident"]["tags"]  # cleaned to safe characters
    ui.patch(f"/api/soc/incidents/{iid}", json={"remove_tag": "escalate-now"})
    ui.post(f"/api/soc/incidents/{iid}/notes", json={"text": "Called the account owner."})
    d = ui.get(f"/api/soc/incidents/{iid}").get_json()
    kinds = [n["kind"] for n in d["notes"]]
    assert kinds[0] == "opened" and "assign" in kinds and "tag" in kinds and kinds[-1] == "note"
    assert ui.get("/api/soc/incidents?assignee=Stacey-Lee").get_json()[0]["id"] == iid


@pytest.mark.parametrize("body,code", [
    ({"status": "done"}, 422), ({"severity": "urgent"}, 422),
])
def test_invalid_updates(ui, body, code):
    ui.post("/api/soc/sync", json={})
    iid = ui.get("/api/soc/incidents").get_json()[0]["id"]
    assert ui.patch(f"/api/soc/incidents/{iid}", json=body).status_code == code


def test_manual_incident_from_app_risk(ui):
    r = ui.post("/api/soc/incidents", json={"title": "Risky Android app: kd-z", "severity": "high",
                                            "summary": "Scored 0.99.", "tags": ["mobile-malware"],
                                            "assessment_id": "abc"})
    assert r.status_code == 201 and r.get_json()["source"] == "manual"
    assert ui.post("/api/soc/incidents", json={"title": ""}).status_code == 422
    assert ui.get("/api/soc/incidents/9999").status_code == 404


def test_overview_numbers(ui):
    ui.post("/api/soc/sync", json={})
    o = ui.get("/api/soc/overview").get_json()
    t = o["totals"]
    assert t["failed_signins"] == 7 and t["records_viewed"] == 250 + 294
    assert t["apps_checked"] == 2 and t["apps_flagged"] == 1
    assert o["incidents"]["open"] == 6 and o["model"]["alarm_accuracy"] > 0.9
    assert o["recent"][0]["time"] >= o["recent"][-1]["time"]


def test_pages_render_and_require_login(ui):
    for path in ("/security", "/security/incidents", "/mobile-risk", "/", "/login"):
        assert ui.get(path).status_code == 200, path
    with banking_app.app.test_client() as anon:
        assert anon.get("/security").status_code == 302
        assert anon.get("/api/soc/overview").status_code == 401


def test_search_and_funnel(ui):
    ui.post("/api/soc/sync", json={})
    r = ui.get("/api/soc/events?q=failed jdoe").get_json()
    assert len(r["results"]) == 6 and all("jdoe" in e["details"] for e in r["results"])
    assert ui.get("/api/soc/events?q=").status_code == 422
    o = ui.get("/api/soc/overview").get_json()
    stages = [f["value"] for f in o["funnel"]]
    assert stages[0] == 18 and stages[2] == 6 and stages[0] >= stages[1] >= stages[2] >= stages[3] >= stages[4]
    assert o["insight"]["account"] == "jdoe" and o["insight"]["headline"] == "54%"


def test_reviewer_suggestion_and_review_flow(ui):
    ui.post("/api/soc/sync", json={})
    iid = ui.get("/api/soc/incidents").get_json()[0]["id"]
    ui.patch(f"/api/soc/incidents/{iid}", json={"assignee": "jdoe"})
    s = ui.get(f"/api/soc/incidents/{iid}/suggest-reviewer").get_json()
    assert s["suggested"] not in ("jdoe", "analyst") and s["reason"]  # not the handler, not the requester
    # reviewer cannot be the person handling it
    assert ui.post(f"/api/soc/incidents/{iid}/review", json={"reviewer": "jdoe"}).status_code == 422
    assert ui.post(f"/api/soc/incidents/{iid}/review", json={"action": "request"}).status_code == 422  # no reviewer yet
    ui.post(f"/api/soc/incidents/{iid}/review", json={"reviewer": "admin"})
    r = ui.post(f"/api/soc/incidents/{iid}/review", json={"action": "request"}).get_json()
    assert r["incident"]["review_status"] == "requested"
    assert ui.post(f"/api/soc/incidents/{iid}/review", json={"action": "approve"}).status_code == 403  # analyst is not the reviewer
    assert ui.get("/api/soc/incidents?review=waiting").get_json()[0]["id"] == iid
    with banking_app.app.test_client() as admin:
        with admin.session_transaction() as sess:
            sess["username"] = "admin"
        assert admin.post(f"/api/soc/incidents/{iid}/review", json={"action": "approve"}).get_json()["incident"]["review_status"] == "approved"


def test_nobody_handles_or_reviews_an_incident_about_themselves(ui):
    ui.post("/api/soc/sync", json={})
    inc = next(i for i in ui.get("/api/soc/incidents").get_json() if i["entity"] == "jdoe")
    iid = inc["id"]
    assert ui.patch(f"/api/soc/incidents/{iid}", json={"assignee": "jdoe"}).status_code == 422
    assert ui.post(f"/api/soc/incidents/{iid}/review", json={"reviewer": "jdoe"}).status_code == 422
    s = ui.get(f"/api/soc/incidents/{iid}/suggest-reviewer").get_json()
    assert s["suggested"] != "jdoe" and "jdoe" not in [c["name"] for c in s["candidates"]]


def test_tasks_tag_people_and_my_work(ui):
    ui.post("/api/soc/sync", json={})
    iid = ui.get("/api/soc/incidents").get_json()[1]["id"]
    d = ui.post(f"/api/soc/incidents/{iid}/tasks", json={"assignee": "analyst", "text": "Check device logs"}).get_json()
    tid = d["tasks"][0]["id"]
    assert ui.post(f"/api/soc/incidents/{iid}/tasks", json={"assignee": "", "text": "x"}).status_code == 422
    mine = [i["id"] for i in ui.get("/api/soc/incidents?involving=me").get_json()]
    assert iid in mine
    w = {x["name"]: x for x in ui.get("/api/soc/overview").get_json()["workload"]}
    assert w["analyst"]["tasks"] == 1
    d = ui.patch(f"/api/soc/incidents/{iid}/tasks/{tid}", json={"done": True}).get_json()
    assert d["tasks"][0]["done"] == 1 and any("Completed task" in n["text"] for n in d["notes"])
    assert iid not in [i["id"] for i in ui.get("/api/soc/incidents?involving=me").get_json()]
    o = ui.get("/api/soc/overview").get_json()
    assert len(o["by_hour"]) == 24 and o["open_by_type"]
