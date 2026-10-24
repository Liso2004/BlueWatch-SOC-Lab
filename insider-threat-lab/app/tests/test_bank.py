import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import banking_app  # noqa: E402
import bank  # noqa: E402


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBILE_RISK_DB", str(tmp_path / "bw.db"))
    cache = tmp_path / "nvd"
    cache.mkdir()
    (cache / "android-14.0.json").write_text(json.dumps({"matched": [
        {"match_confidence": "exact", "cvss": {"severity": "CRITICAL"}},
        {"match_confidence": "exact", "cvss": {"severity": "CRITICAL"}},
        {"match_confidence": "range", "cvss": {"severity": "HIGH"}},
        {"match_confidence": "unspecified", "cvss": {"severity": "CRITICAL"}},  # not counted
    ]}))
    monkeypatch.setattr(bank, "NVD_CACHE", cache)


@pytest.fixture
def ui():
    with banking_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["username"] = "analyst"
        yield c


def total_balance():
    with bank.connect() as conn:
        return round(sum(r[0] for r in conn.execute("SELECT balance FROM bank_accounts")), 2)


def test_overview_seeds_accounts(ui):
    o = ui.get("/api/bank/overview").get_json()
    assert o["accounts"] >= 8 and o["total_balance"] > 0 and o["recent"] == []


def test_simulate_conserves_money(ui):
    before = total_balance()
    r = ui.post("/api/bank/simulate", json={"n": 10}).get_json()
    assert r["created"] >= 1
    assert total_balance() == pytest.approx(before, abs=0.01)  # transfers conserve total
    assert ui.post("/api/bank/simulate", json={"n": 0}).status_code == 422


def test_cve_context_reads_cache_only():
    ctx = bank.cve_context("14.0")
    assert ctx["critical"] == 2 and ctx["high"] == 1 and ctx["total"] == 3
    assert bank.cve_context("99.0") is None  # no cache file -> no live fetch


def test_fraud_engine_flags_risky_device_with_reason():
    bank.connect().close()
    victim = bank.mark_device_risk("Diana Evans", 0.97, "sideloaded app flagged", "14.0", "a-1")
    assert victim and victim["device_risk"] == 0.97
    flag, reason = bank.assess_payment(victim, 38500.0, "transfer")
    assert flag and "BlueWatch flagged" in reason
    assert "Android 14.0" in reason and "2 known critical vulnerabilities" in reason and "do not block" in reason
    # a small payment from the same account is not flagged
    assert bank.assess_payment(victim, 300.0, "payment")[0] is False


def test_scenario_opens_incident_and_flags_transfer(ui):
    before = total_balance()
    r = ui.post("/api/bank/scenario/compromised-device", json={"victim": "Diana Evans"})
    assert r.status_code == 201
    d = r.get_json()
    assert d["app_risk"]["verdict"] == "flag_for_review"
    assert d["transfer"]["flagged"] == 1 and d["transfer"]["amount"] > 0
    assert d["cve"]["critical"] == 2 and d["incident_id"]
    assert total_balance() == pytest.approx(before, abs=0.01)
    # the incident is in the Security Center, tagged for fraud/account-takeover
    inc = ui.get(f"/api/soc/incidents/{d['incident_id']}").get_json()
    assert set(inc["tags"]) >= {"mobile-malware", "account-takeover", "fraud"}
    assert inc["assessment_id"] and inc["severity"] == "high"
    assert ui.post("/api/bank/scenario/compromised-device", json={"victim": "Nobody"}).status_code == 404


def test_login_required():
    with banking_app.app.test_client() as anon:
        assert anon.get("/api/bank/overview").status_code == 401
        assert anon.post("/api/bank/simulate", json={}).status_code == 401
