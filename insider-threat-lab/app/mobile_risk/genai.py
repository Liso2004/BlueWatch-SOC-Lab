"""
Generative AI case brief for analysts, written by an LLM (Claude or a free local model)
from an assessment's facts.

Guardrails, in order:
  1. The model sees only the assessment facts (verdict, score, evidence, behaviour profile,
     known limitation) - no analyst names, customer data or API keys.
  2. The model is told to use only those facts, not to claim confirmed malware, and not to
     recommend blocking anyone.
  3. Grounding check on the output: every number must come from the facts (allowing
     rounding and percentages) and banned claims are rejected.
  4. Any failure (no key, API error, refusal, grounding failure) falls back to a
     deterministic template, and the response says which one the analyst is reading.

The brief never changes the score or verdict.

Configuration (.env):
  AI_PROVIDER=ollama     free local model via Ollama (AI_MODEL default qwen2.5:1.5b, OLLAMA_URL)
  AI_PROVIDER=anthropic  Claude via the Anthropic SDK (AI_API_KEY; AI_MODEL default claude-opus-5-5)
"""

import json
import os
import re

import anthropic
import requests

DEFAULT_MODEL = "claude-opus-5-5"
OLLAMA_DEFAULT_MODEL = "qwen2.5:1.5b"
# Server-side refusal fallback ("default" routing) is accepted for these models on the Claude API.
FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}

SYSTEM_PROMPT = (
    "You write short case briefs for bank security analysts who review Android app risk "
    "assessments produced by BlueWatch Mobile, a machine-learning triage tool. The user message "
    "is a JSON object with the facts of one assessment. Use only those facts: do not add malware "
    "family names, CVE identifiers, statistics or numbers that are not in the JSON. The risk "
    "score is decision support, not proof, so never state that the app is confirmed malicious "
    "and never recommend blocking a customer, account or device. The risk score is not a "
    "probability: describe it only as a risk score compared with the review threshold, never as "
    "a likelihood, chance or confidence. State the verdict exactly as given (flagged for review, "
    "or not flagged) and do not contradict it. Never use the words likely, likelihood, probable, "
    "probably, chance, confident or confidence. Begin with a sentence of the form: 'This app "
    "scored <risk_score> against a review threshold of <review_threshold>, so it was flagged for "
    "review' (or 'so it was not flagged'). Then explain in plain English what "
    "drove the result, mention the known limitation if it is relevant, and say what the analyst "
    "should check next. Write 4 to 6 sentences of prose with no headings or lists."
)

BANNED = [
    r"\bconfirmed (?:malware|malicious)\b", r"\bis (?:definitely|certainly) (?:malware|malicious)\b",
    r"\bblock(?:ed|ing)? (?:the )?(?:customer|account|user|device)\b", r"\bsuspend",
    r"\bCVE-\d{4}-\d+\b",
    # The score is uncalibrated: no probability language.
    r"\blikel(?:y|ihood)\b", r"\bprobab(?:le|ly|ility)\b", r"\bchance\b", r"\bconfiden(?:ce|t)\b",
    r"\bcalibrated\b",
]
# Wording that contradicts the verdict.
CONTRADICTS = {
    "not_flagged": [r"(?<!not )(?<!n't )\bflagged (?:for review|the app|it|on)\b", r"\bmodel flagged\b"],
    "flag_for_review": [r"\bnot flagged\b"],
}
NOTICE = ("AI-written summary of the facts above. It does not change the score or verdict; "
          "the analyst decides.")


def _provider():
    """'anthropic' (Claude, needs a key), 'ollama' (free local model) or None (template only)."""
    p = os.getenv("AI_PROVIDER", "").lower()
    if p == "anthropic" and (os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
        return "anthropic"
    if p == "ollama":
        return "ollama"
    return None


def facts_for(result, metrics):
    drift = metrics["splits"].get("B_per_class_temporal", {})
    return {
        "app_reference": result.get("sample_id") or "ad-hoc submission",
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "review_threshold": result["threshold"],
        "score_meaning": result["score_semantics"],
        "top_evidence": [{k: e[k] for k in ("feature", "value", "benign_median", "malware_median",
                                             "direction")} for e in result["evidence"]],
        "behaviour_profile": [
            {"category": c["category"], "status": c["status"],
             "flagged_signals": [{"feature": s["feature"], "kind": s["kind"], "value": s["value"]}
                                 for s in c["signals"] if s["flag"]]}
            for c in result["behaviour_profile"]],
        "model_version": result["model_version"],
        "known_limitation": (
            "On apps newer than its training data, the model wrongly flags "
            f"{round(drift.get('false_positive_rate', 0) * 100, 1)}% of benign apps."),
    }


def _fact_numbers(obj, acc):
    if isinstance(obj, bool):
        return acc
    if isinstance(obj, (int, float)):
        acc.add(float(obj))
    elif isinstance(obj, str):
        acc.update(float(n) for n in re.findall(r"\d+(?:\.\d+)?", obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _fact_numbers(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _fact_numbers(v, acc)
    return acc


def _supported(n, text_n, facts):
    decimals = len(text_n.split(".")[1]) if "." in text_n else 0
    for f in facts:
        for candidate in (f, f * 100):
            if abs(round(candidate, decimals) - n) < 1e-9 or abs(candidate - n) < 1e-9:
                return True
    return n <= 10 and n == int(n)  # small counts ("three signals", "6 features")


def grounding_check(text, facts):
    known = _fact_numbers(facts, set())
    unsupported = []
    for raw in re.findall(r"(?<![\w.-])\d+(?:\.\d+)?", text):
        if not _supported(float(raw), raw, known):
            unsupported.append(raw)
    banned = [p for p in BANNED if re.search(p, text, re.IGNORECASE)]
    contradicts = [p for p in CONTRADICTS.get(facts.get("verdict"), [])
                   if re.search(p, text, re.IGNORECASE)]
    # Permission-style names (READ_SMS, SYSTEM_ALERT_WINDOW) must be ones the facts mention.
    facts_text = json.dumps(facts)
    unknown_features = sorted({f for f in re.findall(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b", text)
                               if f not in facts_text})
    return {"passed": not (unsupported or banned or contradicts or unknown_features),
            "unsupported_numbers": unsupported, "banned_patterns": banned,
            "contradicts_verdict": contradicts, "unknown_features": unknown_features}


def template_brief(facts):
    flagged = facts["verdict"] == "flag_for_review"
    present = [c["category"] for c in facts["behaviour_profile"] if c["status"] == "present"]
    top = ", ".join(e["feature"] for e in facts["top_evidence"][:3])
    parts = [
        f"{facts['app_reference']} scored {facts['risk_score']} against a review threshold of "
        f"{facts['review_threshold']}, so it was "
        f"{'flagged for analyst review' if flagged else 'not flagged'}.",
        f"The features that most separate it from typical benign apps are {top}." if top else "",
        (f"Behaviour categories with signals present: {', '.join(present)}." if present
         else "No tracked banking-malware behaviour category shows signals."),
        facts["known_limitation"],
        ("Check where the app was installed from and what it does with these capabilities before "
         "deciding." if flagged else "Re-assess if the app's permissions or behaviour change."),
    ]
    return " ".join(p for p in parts if p)


def _anthropic_text(facts, client):
    """Claude via the Anthropic SDK. Returns (text, model, failure_reason)."""
    model = os.getenv("AI_MODEL") or DEFAULT_MODEL
    client = client or anthropic.Anthropic(api_key=os.getenv("AI_API_KEY") or None,
                                           timeout=60.0, max_retries=1)
    kwargs = dict(model=model, max_tokens=2000, system=SYSTEM_PROMPT,
                  output_config={"effort": "low"},
                  messages=[{"role": "user", "content": json.dumps(facts, indent=1)}])
    if model in FALLBACK_MODELS:
        kwargs.update(betas=["server-side-fallback-2026-07-01"], fallbacks="default")
    try:
        response = client.beta.messages.create(**kwargs)
    except anthropic.AuthenticationError:
        return None, model, "Claude API key rejected"
    except anthropic.RateLimitError:
        return None, model, "Claude API rate limit reached"
    except anthropic.APIStatusError as e:
        return None, model, f"Claude API error {e.status_code}"
    except anthropic.APIConnectionError:
        return None, model, "Could not reach the Claude API"
    if response.stop_reason == "refusal":
        return None, model, "Claude declined this request"
    return " ".join(b.text for b in response.content if b.type == "text").strip(), response.model, None


def _ollama_text(facts, session=requests):
    """Free local model through Ollama (no data leaves the machine). Returns (text, model, reason)."""
    model = os.getenv("AI_MODEL") or OLLAMA_DEFAULT_MODEL
    url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/") + "/api/chat"
    try:
        r = session.post(url, timeout=180, json={
            "model": model, "stream": False, "options": {"temperature": 0.2},
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(facts, indent=1)}]})
    except requests.RequestException:
        return None, model, f"Could not reach the local Ollama model at {url}"
    if r.status_code != 200:
        return None, model, f"Ollama error {r.status_code} (is the model pulled? ollama pull {model})"
    return (r.json().get("message") or {}).get("content", "").strip(), model, None


def case_brief(result, metrics, client=None, provider=None):
    facts = facts_for(result, metrics)
    base = {"notice": NOTICE, "facts_sent": facts}
    provider = provider or ("anthropic" if client is not None else _provider())
    if provider is None:
        return {**base, "summary": template_brief(facts), "generated_by": "template",
                "reason": "Generative AI not configured (set AI_PROVIDER=ollama for the free local "
                          "model, or AI_PROVIDER=anthropic with AI_API_KEY for Claude)"}

    text, model, reason = (_anthropic_text(facts, client) if provider == "anthropic"
                           else _ollama_text(facts))
    if reason is None:
        check = grounding_check(text, facts)
        if text and check["passed"]:
            return {**base, "summary": text, "generated_by": "ai", "provider": provider,
                    "model": model, "grounding": check}
        reason = "AI summary failed the grounding check" if text else "Empty AI response"
        base["rejected_ai_summary"] = {"text": text, "grounding": check, "model": model}
    return {**base, "summary": template_brief(facts), "generated_by": "template", "reason": reason}
