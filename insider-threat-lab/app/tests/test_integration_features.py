import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import banking_app  # noqa: E402
import mobile_risk  # noqa: E402
from mobile_risk import apikeys, store  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBILE_RISK_DB", str(tmp_path / "bw.db"))


@pytest.fixture
def ui():
    with banking_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["username"] = "analyst"
        yield c


@pytest.fixture
def api_key(monkeypatch):
    key, entry = apikeys.new_key("soc-siem")
    monkeypatch.setenv("BLUEWATCH_API_KEYS", entry)
    return key


@pytest.fixture
def api():
    with banking_app.app.test_client() as c:
        yield c


def first_sample(ui, label):
    return next(s["sample_id"] for s in ui.get("/api/mobile/samples").get_json()
                if s["expected_label"] == label)


# --- API v1 (system-to-system) -------------------------------------------------------------

def test_v1_requires_valid_key(api, api_key):
    assert api.post("/api/v1/mobile/assess", json={"features": {"SEND_SMS": 1}}).status_code == 401
    r = api.post("/api/v1/mobile/assess", json={"features": {"SEND_SMS": 1}},
                 headers={"X-API-Key": "bwm_wrong"})
    assert r.status_code == 401


def test_v1_does_not_accept_browser_session(ui, api_key):
    assert ui.post("/api/v1/mobile/assess", json={"features": {"SEND_SMS": 1}}).status_code == 401


def test_v1_assess_records_client(api, api_key):
    r = api.post("/api/v1/mobile/assess", json={"sample_id": "bank-app-123",
                                                "features": {"SEND_SMS": 1, "RECEIVE_SMS": 1}},
                 headers={"X-API-Key": api_key})
    assert r.status_code == 200
    body = r.get_json()
    assert body["assessment_id"] and body["sample_id"] == "bank-app-123"
    row = store.recent(1)[0]
    assert row["actor"] == "api:soc-siem" and row["channel"] == "api-v1"


def test_v1_model_lists_feature_schema(api, api_key):
    m = api.get("/api/v1/mobile/model", headers={"X-API-Key": api_key}).get_json()
    assert len(m["feature_names"]) == m["n_features"] and m["platform"] == "Android only"


def test_no_keys_configured_means_api_closed(api, monkeypatch):
    monkeypatch.delenv("BLUEWATCH_API_KEYS", raising=False)
    assert api.get("/api/v1/mobile/model", headers={"X-API-Key": "anything"}).status_code == 401


def test_keys_are_stored_as_hashes_only():
    key, entry = apikeys.new_key("fraud-engine")
    assert key not in entry and entry == f"fraud-engine:{apikeys.hash_key(key)}"
    with pytest.raises(ValueError):
        apikeys.new_key("Bad Name!")


# --- feedback loop ------------------------------------------------------------------------

def test_feedback_flow_and_export(ui):
    mal = ui.post("/api/mobile/assess", json={"sample_id": first_sample(ui, "malware")}).get_json()
    assert mal["verdict"] == "flag_for_review"
    r = ui.post("/api/mobile/feedback", json={"assessment_id": mal["assessment_id"],
                                              "label": "confirmed_malicious"})
    assert r.status_code == 200

    ben = ui.post("/api/mobile/assess", json={"sample_id": first_sample(ui, "benign")}).get_json()
    ui.post("/api/mobile/feedback", json={"assessment_id": ben["assessment_id"],
                                          "label": "confirmed_benign"})

    activity = ui.get("/api/mobile/activity").get_json()
    assert activity["summary"]["assessments"] == 2
    assert activity["summary"]["analyst_precision"] == 1.0
    assert {r["feedback"] for r in activity["recent"]} == {"confirmed_malicious", "confirmed_benign"}

    export = ui.get("/api/mobile/feedback/export")
    rows = [json.loads(line) for line in export.data.decode().splitlines()]
    assert sorted(r["label"] for r in rows) == [0, 1]
    assert all(r["features"] and r["scored_by_model"] for r in rows)


@pytest.mark.parametrize("label,status", [
    ("confirmed_benign", 422),   # does not apply to a flagged assessment
    ("not_a_label", 422),
])
def test_feedback_rejects_inconsistent_labels(ui, label, status):
    mal = ui.post("/api/mobile/assess", json={"sample_id": first_sample(ui, "malware")}).get_json()
    r = ui.post("/api/mobile/feedback", json={"assessment_id": mal["assessment_id"], "label": label})
    assert r.status_code == status


def test_feedback_unknown_assessment(ui):
    r = ui.post("/api/mobile/feedback", json={"assessment_id": "nope", "label": "false_positive"})
    assert r.status_code == 404


def test_feedback_requires_login(api):
    assert api.post("/api/mobile/feedback", json={}).status_code == 401


def test_sample_features_endpoint(ui):
    sid = first_sample(ui, "malware")
    f = ui.get(f"/api/mobile/samples/{sid}/features").get_json()
    assert isinstance(f, dict) and f
    assert ui.get("/api/mobile/samples/nope/features").status_code == 404


# --- configuration --------------------------------------------------------------------------

def test_threshold_override(monkeypatch):
    monkeypatch.setenv("MOBILE_RISK_THRESHOLD", "0.8")
    m = mobile_risk.MobileRiskModel()
    assert m.threshold == 0.8
    assert m.assess({"SEND_SMS": 1})["threshold"] == 0.8
    monkeypatch.setenv("MOBILE_RISK_THRESHOLD", "1.5")
    with pytest.raises(ValueError):
        mobile_risk.MobileRiskModel()


def test_security_defaults():
    src = (Path(banking_app.__file__)).read_text()
    assert "debug=True" not in src
    assert banking_app.app.config["MAX_CONTENT_LENGTH"] == 256 * 1024


def test_library_log_records_do_not_break_formatter(caplog):
    import logging
    record = logging.LogRecord("werkzeug", logging.INFO, __file__, 1, "hello", None, None)
    banking_app.SocLogDefaults().filter(record)
    fmt = logging.Formatter('%(message)s - USER:%(user)s - IP:%(ip)s')
    assert fmt.format(record) == "hello - USER:- - IP:-"
