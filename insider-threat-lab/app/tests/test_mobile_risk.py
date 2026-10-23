import os
import sys
import tempfile
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))
LOG_FILE = Path(tempfile.gettempdir()) / "bluewatch_test_banking_app.log"
os.environ["APP_LOG_FILE"] = str(LOG_FILE)

import banking_app  # noqa: E402


@pytest.fixture
def client():
    banking_app.app.config["TESTING"] = True
    with banking_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["username"] = "analyst"
        yield c


@pytest.fixture
def anon():
    with banking_app.app.test_client() as c:
        yield c


def test_requires_login(anon):
    assert anon.get("/api/mobile/samples").status_code == 401
    assert anon.post("/api/mobile/assess", json={"sample_id": "x"}).status_code == 401
    assert anon.get("/mobile-risk").status_code == 302


def test_page_renders(client):
    r = client.get("/mobile-risk")
    assert r.status_code == 200
    assert b"decision support only" in r.data


def test_samples_are_three_malware_three_benign(client):
    samples = client.get("/api/mobile/samples").get_json()
    labels = sorted(s["expected_label"] for s in samples)
    assert labels == ["benign"] * 3 + ["malware"] * 3
    assert "features" not in samples[0]


def test_model_info_reports_all_splits(client):
    m = client.get("/api/mobile/model").get_json()
    assert m["model_version"]
    assert set(m["evaluation"]) == {"A_random_stratified", "B_per_class_temporal",
                                    "C_unseen_malware_families"}


def test_assess_each_sample(client):
    for s in client.get("/api/mobile/samples").get_json():
        r = client.post("/api/mobile/assess", json={"sample_id": s["sample_id"]})
        assert r.status_code == 200
        body = r.get_json()
        assert body["verdict"] in {"flag_for_review", "not_flagged"}
        assert 0.0 <= body["risk_score"] <= 1.0
        assert (body["risk_score"] >= body["threshold"]) == (body["verdict"] == "flag_for_review")
        assert body["expected_label"] == s["expected_label"]
        assert body["model_version"] and body["features_version"] and body["disclaimer"]
        assert len(body["evidence"]) > 0


def test_assess_adhoc_features(client):
    r = client.post("/api/mobile/assess",
                    json={"features": {"SEND_SMS": 1, "RECEIVE_SMS": 1, "READ_PHONE_STATE": 1}})
    assert r.status_code == 200
    body = r.get_json()
    assert body["sample_id"] is None
    assert {i["feature"] for i in body["banking_indicators_present"]} >= {"SEND_SMS", "RECEIVE_SMS"}


@pytest.mark.parametrize("payload,status", [
    ({"features": {"NOT_A_FEATURE": 1}}, 422),
    ({"features": {"SEND_SMS": -1}}, 422),
    ({"features": {"SEND_SMS": "yes"}}, 422),
    ({"features": {"SEND_SMS": True}}, 422),
    ({"features": {}}, 422),
    ({"features": [1, 2, 3]}, 422),
    ({"sample_id": "kd-doesnotexist"}, 404),
    ({}, 422),
])
def test_invalid_requests(client, payload, status):
    r = client.post("/api/mobile/assess", json=payload)
    assert r.status_code == status
    assert "error" in r.get_json()


def test_non_json_body(client):
    r = client.post("/api/mobile/assess", data="not json", content_type="text/plain")
    assert r.status_code == 400


def test_assessment_is_logged_for_soc(client, caplog):
    s = client.get("/api/mobile/samples").get_json()[0]
    with caplog.at_level("INFO"):
        client.post("/api/mobile/assess", json={"sample_id": s["sample_id"]})
    rec = next(r for r in caplog.records if "MOBILE_RISK_ASSESSMENT" in r.getMessage())
    assert f"Sample: {s['sample_id']}" in rec.getMessage()
    assert rec.user == "analyst"
