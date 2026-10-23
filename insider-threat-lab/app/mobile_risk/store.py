"""
Audit trail and analyst feedback for BlueWatch Mobile.

Every assessment is recorded with the model/feature versions that produced it, so a bank can
show later why an app was flagged. Analyst feedback on an assessment becomes a labelled row
that a future training run can use (see export_labelled). SQLite keeps this self-contained;
the database path is MOBILE_RISK_DB.

Stored per assessment: the app's feature counts (no personal data), the verdict, score,
threshold, versions, and who/which client asked. Nothing about the device owner is stored.
"""

import json
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

FEEDBACK_LABELS = {
    "confirmed_malicious": "Analyst confirmed the app is malicious",
    "false_positive": "Flagged, but the analyst found it benign",
    "confirmed_benign": "Not flagged, and the analyst agrees it is benign",
    "missed_malware": "Not flagged, but the analyst found it malicious",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    channel TEXT NOT NULL,
    sample_id TEXT,
    verdict TEXT NOT NULL,
    risk_score REAL NOT NULL,
    threshold REAL NOT NULL,
    model_version TEXT NOT NULL,
    features_version TEXT NOT NULL,
    features_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id),
    created_at TEXT NOT NULL,
    analyst TEXT NOT NULL,
    label TEXT NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS feedback_assessment ON feedback(assessment_id);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path():
    return Path(os.getenv("MOBILE_RISK_DB",
                          Path(tempfile.gettempdir()) / "bluewatch-mobile" / "bluewatch_mobile.db"))


def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def record_assessment(result, features, actor, channel):
    assessment_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute(
            "INSERT INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (assessment_id, _now(), actor, channel, result.get("sample_id"), result["verdict"],
             result["risk_score"], result["threshold"], result["model_version"],
             result["features_version"], json.dumps(features, sort_keys=True)))
    return assessment_id


class FeedbackError(ValueError):
    pass


def add_feedback(assessment_id, label, analyst, note=None):
    if label not in FEEDBACK_LABELS:
        raise FeedbackError(f"label must be one of {sorted(FEEDBACK_LABELS)}")
    if note is not None and (not isinstance(note, str) or len(note) > 500):
        raise FeedbackError("note must be text of at most 500 characters")
    with connect() as conn:
        row = conn.execute("SELECT verdict FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if row is None:
            raise LookupError(f"unknown assessment_id '{assessment_id}'")
        flagged = row["verdict"] == "flag_for_review"
        if flagged and label in ("confirmed_benign", "missed_malware"):
            raise FeedbackError(f"'{label}' does not apply to a flagged assessment")
        if not flagged and label in ("confirmed_malicious", "false_positive"):
            raise FeedbackError(f"'{label}' does not apply to an unflagged assessment")
        conn.execute("INSERT INTO feedback (assessment_id, created_at, analyst, label, note) "
                     "VALUES (?,?,?,?,?)", (assessment_id, _now(), analyst, label, note))
    return {"assessment_id": assessment_id, "label": label, "meaning": FEEDBACK_LABELS[label]}


def get_features(assessment_id):
    with connect() as conn:
        row = conn.execute("SELECT sample_id, features_json FROM assessments WHERE id = ?",
                           (assessment_id,)).fetchone()
    if row is None:
        raise LookupError(f"unknown assessment_id '{assessment_id}'")
    return row["sample_id"], json.loads(row["features_json"])


def summary():
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        flagged = conn.execute(
            "SELECT COUNT(*) FROM assessments WHERE verdict = 'flag_for_review'").fetchone()[0]
        labels = {r["label"]: r["n"] for r in conn.execute(
            "SELECT label, COUNT(*) AS n FROM feedback GROUP BY label")}
    reviewed_flags = labels.get("confirmed_malicious", 0) + labels.get("false_positive", 0)
    return {
        "assessments": total,
        "flagged": flagged,
        "feedback": {k: labels.get(k, 0) for k in FEEDBACK_LABELS},
        "analyst_precision": round(labels.get("confirmed_malicious", 0) / reviewed_flags, 4)
                             if reviewed_flags else None,
        "note": "analyst_precision = confirmed_malicious / (confirmed_malicious + false_positive), "
                "over flagged assessments analysts have reviewed. Not a model metric.",
    }


def recent(limit=20):
    with connect() as conn:
        rows = conn.execute(
            """SELECT a.id, a.created_at, a.actor, a.channel, a.sample_id, a.verdict, a.risk_score,
                      a.model_version, f.label AS feedback, f.analyst AS reviewed_by
               FROM assessments a
               LEFT JOIN feedback f ON f.id = (SELECT MAX(id) FROM feedback WHERE assessment_id = a.id)
               ORDER BY a.created_at DESC, a.rowid DESC LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]


def export_labelled():
    """Assessments with their latest analyst label, as training candidates.
    Label mapping: confirmed_malicious/missed_malware -> 1, false_positive/confirmed_benign -> 0."""
    to_y = {"confirmed_malicious": 1, "missed_malware": 1, "false_positive": 0, "confirmed_benign": 0}
    with connect() as conn:
        rows = conn.execute(
            """SELECT a.id, a.features_json, a.model_version, a.features_version, f.label, f.created_at
               FROM assessments a JOIN feedback f
                 ON f.id = (SELECT MAX(id) FROM feedback WHERE assessment_id = a.id)""").fetchall()
    for r in rows:
        yield {"assessment_id": r["id"], "label": to_y[r["label"]], "analyst_label": r["label"],
               "labelled_at": r["created_at"], "scored_by_model": r["model_version"],
               "features_version": r["features_version"], "features": json.loads(r["features_json"])}
