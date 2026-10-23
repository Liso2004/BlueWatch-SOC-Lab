"""
BlueWatch Mobile - Android app risk triage for SOC analysts.

Scores pre-extracted Android app features (system-call counts, permissions and manifest
counts, KronoDroid schema) with a Random Forest baseline and returns the score with
supporting evidence. Output is decision support for human review; nothing here blocks
accounts or devices.

Artifacts are produced by bluewatch-mobile/ml/train.py.
"""

import json
import math
import os
import time
from pathlib import Path

import joblib
import numpy as np
from flask import (Blueprint, Response, current_app, g, jsonify, redirect, render_template,
                   request, session)

from . import apikeys, behaviour, genai, nvd, store

ARTIFACTS = Path(__file__).parent / "artifacts"

# Permissions associated with Android banking-trojan techniques (overlay, accessibility
# abuse, SMS/OTP interception, notification reading, payload install, device admin).
# Shown as context only: each has legitimate uses and none is proof of malware.
BANKING_INDICATORS = {
    "SYSTEM_ALERT_WINDOW": "Can draw overlays over other apps",
    "BIND_ACCESSIBILITY_SERVICE": "Declares an accessibility service",
    "RECEIVE_SMS": "Can receive SMS (OTP interception risk)",
    "READ_SMS": "Can read SMS",
    "SEND_SMS": "Can send SMS",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Can read notifications",
    "REQUEST_INSTALL_PACKAGES": "Can request installing other packages",
    "BIND_DEVICE_ADMIN": "Requests device-admin capability",
    "RECEIVE_BOOT_COMPLETED": "Starts at boot (persistence)",
}

DISCLAIMER = ("Decision support only. A high score means 'prioritise for analyst review', "
              "not 'confirmed malware'. Do not block accounts or devices on this score alone.")


class ValidationError(ValueError):
    pass


def configured_threshold(default):
    """Each bank sets its review threshold (MOBILE_RISK_THRESHOLD, 0-1) to match analyst capacity."""
    raw = os.getenv("MOBILE_RISK_THRESHOLD")
    if not raw:
        return default
    value = float(raw)
    if not 0 < value < 1:
        raise ValueError("MOBILE_RISK_THRESHOLD must be between 0 and 1")
    return value


class MobileRiskModel:
    def __init__(self, artifacts=ARTIFACTS):
        self.model = joblib.load(artifacts / "model.joblib")
        meta = json.loads((artifacts / "model_meta.json").read_text())
        self.meta = meta
        self.names = meta["feature_names"]
        self.index = {n: i for i, n in enumerate(self.names)}
        self.importance = np.array(meta["importance"])
        self.benign_median = np.array(meta["benign_median"])
        self.benign_p90 = np.array(meta["benign_p90"])
        self.malware_median = np.array(meta["malware_median"])
        self.threshold = configured_threshold(meta["threshold"])
        self.metrics = json.loads((artifacts / "metrics.json").read_text())
        self.samples = json.loads((artifacts / "demo_samples.json").read_text())

    def vectorize(self, features):
        """Missing features are treated as 0 (not observed), matching prepare.py."""
        if not isinstance(features, dict) or not features:
            raise ValidationError("'features' must be a non-empty object of name -> number")
        unknown = sorted(set(features) - set(self.index))
        if unknown:
            raise ValidationError(f"unknown feature names: {unknown[:10]}"
                                  + (" ..." if len(unknown) > 10 else ""))
        x = np.zeros(len(self.names))
        for name, value in features.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(value) or value < 0:
                raise ValidationError(f"feature '{name}' must be a finite number >= 0")
            x[self.index[name]] = value
        return x

    def evidence(self, x, k=6):
        """Features where this app departs most from typical benign training apps,
        weighted by global model importance. Supporting evidence, not a causal explanation."""
        spread = np.maximum(self.benign_p90 - self.benign_median, 1.0)
        deviation = (x - self.benign_median) / spread
        weight = self.importance * np.abs(deviation)
        out = []
        for i in np.argsort(-weight)[:k]:
            if weight[i] <= 0:
                break
            out.append({
                "feature": self.names[i],
                "value": float(x[i]),
                "benign_median": float(self.benign_median[i]),
                "malware_median": float(self.malware_median[i]),
                "direction": "higher than typical benign" if deviation[i] > 0
                             else "lower than typical benign",
                "model_importance": round(float(self.importance[i]), 4),
            })
        return out

    def assess(self, features):
        x = self.vectorize(features)
        t0 = time.perf_counter()
        score = float(self.model.predict_proba(x.reshape(1, -1))[0, 1])
        latency_ms = (time.perf_counter() - t0) * 1000
        flagged = score >= self.threshold
        return {
            "verdict": "flag_for_review" if flagged else "not_flagged",
            "risk_score": round(score, 4),
            "threshold": self.threshold,
            "score_semantics": self.meta["score_semantics"],
            "evidence": self.evidence(x),
            "behaviour_profile": behaviour.profile(x, self.index, self.benign_p90),
            "banking_indicators_present": [
                {"feature": f, "meaning": m} for f, m in BANKING_INDICATORS.items()
                if f in self.index and x[self.index[f]] > 0],
            "features_provided": len(features),
            "features_missing_filled_zero": len(self.names) - len(features),
            "model_version": self.meta["model_version"],
            "features_version": self.meta["features_version"],
            "inference_ms": round(latency_ms, 2),
            "disclaimer": DISCLAIMER,
        }


bp = Blueprint("mobile_risk", __name__)
api_v1 = Blueprint("mobile_risk_api_v1", __name__, url_prefix="/api/v1/mobile")
_model = None


def get_model():
    global _model
    if _model is None:
        _model = MobileRiskModel()
    return _model


def _soc_log(event, details, actor):
    # Reuse the banking app's SOC log format so Logstash/Wazuh ingest these events too.
    current_app.logger.info(f"{event}: {details}", extra={"user": actor, "ip": request.remote_addr})


# --- shared handlers (analyst UI and v1 API) ---------------------------------------------

def _assess(actor, channel):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    m = get_model()
    sample_id = body.get("sample_id")
    features = body.get("features")
    expected = None
    if features is None and sample_id:
        match = next((s for s in m.samples if s["sample_id"] == sample_id), None)
        if match is None:
            return jsonify({"error": f"unknown sample_id '{sample_id}'"}), 404
        features, expected = match["features"], match["expected_label"]
    elif sample_id is not None and (not isinstance(sample_id, str) or len(sample_id) > 100):
        return jsonify({"error": "sample_id must be text of at most 100 characters"}), 422
    try:
        result = m.assess(features)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 422
    result["sample_id"] = sample_id
    result["expected_label"] = expected
    result["assessment_id"] = store.record_assessment(result, features, actor, channel)
    _soc_log("MOBILE_RISK_ASSESSMENT",
             f"Assessment: {result['assessment_id']} | Sample: {sample_id or 'adhoc'} | "
             f"Channel: {channel} | Verdict: {result['verdict']} | Score: {result['risk_score']} | "
             f"Threshold: {result['threshold']} | Model: {result['model_version']}", actor)
    return jsonify(result)


def _feedback(analyst):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    try:
        out = store.add_feedback(str(body.get("assessment_id", "")), body.get("label"),
                                 analyst, body.get("note"))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except store.FeedbackError as e:
        return jsonify({"error": str(e)}), 422
    _soc_log("MOBILE_RISK_FEEDBACK", f"Assessment: {out['assessment_id']} | Label: {out['label']}",
             analyst)
    return jsonify(out)


def _brief(actor):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    assessment_id = str(body.get("assessment_id", ""))
    try:
        sample_id, features = store.get_features(assessment_id)
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    m = get_model()
    result = m.assess(features)
    result["sample_id"] = sample_id
    out = genai.case_brief(result, m.metrics)
    out["assessment_id"] = assessment_id
    _soc_log("GENAI_CASE_BRIEF",
             f"Assessment: {assessment_id} | Source: {out['generated_by']}"
             + (f" | Model: {out['model']}" if out.get("model") else "")
             + (f" | Fallback reason: {out['reason']}" if out.get("reason") else ""), actor)
    return jsonify(out)


def _model_info():
    m = get_model()
    return jsonify({
        "model_version": m.meta["model_version"],
        "features_version": m.meta["features_version"],
        "algorithm": m.meta["algorithm"],
        "trained_on": m.meta["trained_on"],
        "trained_at_utc": m.meta["trained_at_utc"],
        "dataset": {k: m.meta["dataset"][k] for k in ("name", "url", "citation")},
        "n_features": len(m.names),
        "feature_names": m.names,
        "threshold": m.threshold,
        "model_default_threshold": m.meta["threshold"],
        "score_semantics": m.meta["score_semantics"],
        "evaluation": m.metrics["splits"],
        "platform": "Android only",
    })


def _vulnerabilities(actor):
    """Android OS vulnerability context from NVD. Separate from, and never feeds, the verdict."""
    version = request.args.get("android_version", "")
    if version not in nvd.SUPPORTED_VERSIONS:
        return jsonify({"error": f"android_version must be one of {nvd.SUPPORTED_VERSIONS}"}), 422
    try:
        result = nvd.android_platform_context(version)
    except nvd.NVDError as e:
        return jsonify({"error": f"{e}. Malware assessment is unaffected.",
                        "notice": nvd.NOTICE}), 503
    _soc_log("VULN_CONTEXT_LOOKUP",
             f"Android {version} | Matched exact/range: "
             f"{result['match_counts']['exact'] + result['match_counts']['range']} | "
             f"Source: NVD {result['retrieved_at']}", actor)
    return jsonify(result)


# --- analyst UI (browser session) ----------------------------------------------------------

@bp.before_request
def require_login():
    if "username" not in session:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/login")


@bp.route("/mobile-risk")
def page():
    return render_template("mobile_risk.html", username=session["username"], active="apprisk",
                           feedback_labels=store.FEEDBACK_LABELS)


@bp.route("/api/mobile/model", methods=["GET"])
def model_info():
    return _model_info()


@bp.route("/api/mobile/samples", methods=["GET"])
def samples():
    return jsonify([{k: s[k] for k in ("sample_id", "expected_label", "family", "date", "source")}
                    for s in get_model().samples])


@bp.route("/api/mobile/samples/<sample_id>/features", methods=["GET"])
def sample_features(sample_id):
    match = next((s for s in get_model().samples if s["sample_id"] == sample_id), None)
    if match is None:
        return jsonify({"error": f"unknown sample_id '{sample_id}'"}), 404
    return jsonify(match["features"])


@bp.route("/api/mobile/assess", methods=["POST"])
def assess():
    return _assess(session["username"], "analyst-ui")


@bp.route("/api/mobile/feedback", methods=["POST"])
def feedback():
    return _feedback(session["username"])


@bp.route("/api/mobile/brief", methods=["POST"])
def brief():
    return _brief(session["username"])


@bp.route("/api/mobile/activity", methods=["GET"])
def activity():
    return jsonify({"summary": store.summary(), "recent": store.recent()})


@bp.route("/api/mobile/feedback/export", methods=["GET"])
def feedback_export():
    rows = "".join(json.dumps(r) + "\n" for r in store.export_labelled())
    _soc_log("MOBILE_RISK_LABEL_EXPORT", f"Rows: {rows.count(chr(10))}", session["username"])
    return Response(rows, mimetype="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=bluewatch_labels.jsonl"})


@bp.route("/api/mobile/vulnerabilities", methods=["GET"])
def vulnerabilities():
    return _vulnerabilities(session["username"])


@bp.route("/api/mobile/vulnerabilities/versions", methods=["GET"])
def vulnerability_versions():
    return jsonify(nvd.SUPPORTED_VERSIONS)


# --- v1 API for bank systems (SIEM, SOAR, fraud engine) -------------------------------------

@api_v1.before_request
def require_api_key():
    client = apikeys.client_for(request.headers.get("X-API-Key", ""))
    if client is None:
        current_app.logger.warning("API_AUTH_FAILED: /api/v1/mobile",
                                   extra={"user": "unknown-client", "ip": request.remote_addr})
        return jsonify({"error": "missing or invalid X-API-Key"}), 401
    g.api_client = client


@api_v1.route("/assess", methods=["POST"])
def v1_assess():
    return _assess(f"api:{g.api_client}", "api-v1")


@api_v1.route("/feedback", methods=["POST"])
def v1_feedback():
    return _feedback(f"api:{g.api_client}")


@api_v1.route("/brief", methods=["POST"])
def v1_brief():
    return _brief(f"api:{g.api_client}")


@api_v1.route("/model", methods=["GET"])
def v1_model():
    return _model_info()


@api_v1.route("/vulnerabilities", methods=["GET"])
def v1_vulnerabilities():
    return _vulnerabilities(f"api:{g.api_client}")
