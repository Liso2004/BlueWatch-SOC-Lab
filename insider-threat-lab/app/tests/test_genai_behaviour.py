import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import banking_app  # noqa: E402
import mobile_risk  # noqa: E402
from mobile_risk import genai  # noqa: E402


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBILE_RISK_DB", str(tmp_path / "bw.db"))
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def model():
    return mobile_risk.get_model()


@pytest.fixture
def malware_result(model):
    s = next(s for s in model.samples if s["expected_label"] == "malware")
    r = model.assess(s["features"])
    r["sample_id"] = s["sample_id"]
    return r


class FakeClient:
    def __init__(self, text="", stop_reason="end_turn"):
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))
        self.text, self.stop_reason = text, stop_reason

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(stop_reason=self.stop_reason, model=kwargs["model"],
                               content=[SimpleNamespace(type="text", text=self.text)])


# --- behaviour profile ----------------------------------------------------------------------

def test_profile_covers_brief_categories(malware_result):
    cats = {c["category"]: c for c in malware_result["behaviour_profile"]}
    assert {"Screen overlay", "Accessibility abuse", "SMS / notification interception",
            "Dynamic code / payload loading", "Network behaviour",
            "Persistence / device control", "Screen capture"} == set(cats)
    assert cats["Screen capture"]["status"] == "not available"
    kinds = {s["kind"] for c in cats.values() for s in c["signals"]}
    assert kinds == {"declared permission", "observed at runtime"}


def test_profile_flags_declared_permission(model):
    r = model.assess({"SYSTEM_ALERT_WINDOW": 1})
    overlay = next(c for c in r["behaviour_profile"] if c["category"] == "Screen overlay")
    assert overlay["status"] == "present"


# --- GenAI case brief ---------------------------------------------------------------------------

def test_not_configured_uses_template(model, malware_result):
    out = genai.case_brief(malware_result, model.metrics)
    assert out["generated_by"] == "template" and "not configured" in out["reason"]
    assert str(malware_result["risk_score"]) in out["summary"]


def test_grounded_claude_summary_is_accepted(model, malware_result):
    score = malware_result["risk_score"]
    text = (f"This app scored {score}, above the {malware_result['threshold']} review threshold. "
            "Its permission profile differs from typical benign apps. Check where it was installed "
            "from before deciding.")
    client = FakeClient(text)
    out = genai.case_brief(malware_result, model.metrics, client=client)
    assert out["generated_by"] == "ai" and out["provider"] == "anthropic" and out["grounding"]["passed"]
    call = client.calls[0]
    assert call["model"] == "claude-opus-5-5" and call["fallbacks"] == "default"
    # Only assessment facts are sent: no analyst/client identity, assessment id or raw features
    assert set(out["facts_sent"]) == {"app_reference", "verdict", "risk_score", "review_threshold",
                                      "score_meaning", "top_evidence", "behaviour_profile",
                                      "model_version", "known_limitation"}


@pytest.mark.parametrize("text", [
    "This app scored 0.97 and has been active for 312 days.",           # invented numbers
    "The app is confirmed malware and you should block the customer.",  # banned claims
    "This matches CVE-2025-48626.",                                      # CVE not in facts
])
def test_ungrounded_summary_falls_back(model, malware_result, text):
    out = genai.case_brief(malware_result, model.metrics, client=FakeClient(text))
    assert out["generated_by"] == "template"
    assert out["reason"] == "AI summary failed the grounding check"
    assert not out["rejected_ai_summary"]["grounding"]["passed"]


def test_refusal_falls_back(model, malware_result):
    out = genai.case_brief(malware_result, model.metrics, client=FakeClient("", "refusal"))
    assert out["generated_by"] == "template" and "declined" in out["reason"]


def test_percentages_and_rounding_are_grounded():
    facts = {"risk_score": 0.9433, "known_limitation": "wrongly flags 49.2% of benign apps"}
    assert genai.grounding_check("Scored 0.94 (94%); limitation 49.2%.", facts)["passed"]
    assert not genai.grounding_check("Scored 0.81.", facts)["passed"]


# --- route ----------------------------------------------------------------------------------------

def test_brief_route(model):
    with banking_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["username"] = "analyst"
        sid = next(s["sample_id"] for s in model.samples if s["expected_label"] == "malware")
        a = c.post("/api/mobile/assess", json={"sample_id": sid}).get_json()
        b = c.post("/api/mobile/brief", json={"assessment_id": a["assessment_id"]})
        assert b.status_code == 200 and b.get_json()["generated_by"] == "template"
        assert c.post("/api/mobile/brief", json={"assessment_id": "nope"}).status_code == 404


# --- free local model (Ollama) ---------------------------------------------------------------

class FakeOllama:
    def __init__(self, status=200, text=""):
        self.status, self.text, self.calls = status, text, []

    def post(self, url, timeout, json):
        self.calls.append((url, json))
        return SimpleNamespace(status_code=self.status,
                               json=lambda: {"message": {"role": "assistant", "content": self.text}})


def test_ollama_grounded_summary(model, malware_result, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    fake = FakeOllama(text=f"The app scored {malware_result['risk_score']}; review it before deciding.")
    monkeypatch.setattr(genai.requests, "post", fake.post)
    out = genai.case_brief(malware_result, model.metrics)
    assert out["generated_by"] == "ai" and out["provider"] == "ollama"
    assert out["model"] == "qwen2.5:1.5b"
    url, body = fake.calls[0]
    assert url == "http://localhost:11434/api/chat" and body["stream"] is False
    assert body["messages"][0]["role"] == "system"


def test_ollama_ungrounded_or_unavailable_falls_back(model, malware_result, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setattr(genai.requests, "post", FakeOllama(text="Scored 0.12 over 400 days.").post)
    assert genai.case_brief(malware_result, model.metrics)["reason"] == "AI summary failed the grounding check"
    monkeypatch.setattr(genai.requests, "post", FakeOllama(status=404).post)
    out = genai.case_brief(malware_result, model.metrics)
    assert out["generated_by"] == "template" and "ollama pull" in out["reason"]


@pytest.mark.parametrize("text,key", [
    ("This app scored 0.9433, a high likelihood of malware.", "banned_patterns"),
    ("It probably steals data.", "banned_patterns"),
    ("This app declares BIND_DEVICE_ADMIN_FAKE.", "unknown_features"),
])
def test_stricter_grounding(text, key):
    facts = {"verdict": "flag_for_review", "risk_score": 0.9433}
    g = genai.grounding_check(text, facts)
    assert not g["passed"] and g[key]


def test_contradicting_the_verdict_is_rejected():
    assert not genai.grounding_check("The model flagged the app.", {"verdict": "not_flagged"})["passed"]
    assert genai.grounding_check("It was not flagged for review.", {"verdict": "not_flagged"})["passed"]
    assert not genai.grounding_check("It was not flagged.", {"verdict": "flag_for_review"})["passed"]
