"""
Incident records: one per finding (deduplicated), with severity, status, assignee, tags and a
timeline of notes. Stored in the BlueWatch SQLite database next to the app-risk audit trail.
Detection never overwrites what an analyst has set (status, assignee, tags).
"""

import json
import re
from datetime import datetime, timezone

from mobile_risk import store

STATUSES = {"new": "New", "investigating": "Investigating", "resolved": "Resolved",
            "false_positive": "False alarm"}
SEVERITIES = ("high", "medium", "low")
SUGGESTED_TAGS = ["credential-attack", "insider-threat", "data-exfiltration", "mobile-malware",
                  "api-abuse", "customer-contacted", "escalate", "false-alarm", "needs-evidence"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT UNIQUE,
    rule TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    assignee TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    entity TEXT,
    first_seen TEXT,
    last_seen TEXT,
    event_count INTEGER DEFAULT 0,
    evidence TEXT NOT NULL DEFAULT '[]',
    assessment_id TEXT,
    source TEXT NOT NULL DEFAULT 'detection',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    at TEXT NOT NULL,
    author TEXT NOT NULL,
    kind TEXT NOT NULL,
    text TEXT NOT NULL
);
"""


class IncidentError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    conn = store.connect()
    conn.executescript(SCHEMA)
    return conn


def _row(r):
    d = dict(r)
    d["tags"] = json.loads(d["tags"])
    d["evidence"] = json.loads(d["evidence"])
    d["status_label"] = STATUSES.get(d["status"], d["status"])
    return d


def _note(conn, incident_id, author, kind, text):
    conn.execute("INSERT INTO incident_notes (incident_id, at, author, kind, text) VALUES (?,?,?,?,?)",
                 (incident_id, _now(), author, kind, text))


def sync(findings):
    """Insert new findings; refresh counts/evidence on existing ones. Returns (new, updated)."""
    new = updated = 0
    with connect() as conn:
        for f in findings:
            row = conn.execute("SELECT id, event_count FROM incidents WHERE dedup_key = ?",
                               (f["dedup_key"],)).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO incidents (dedup_key, rule, title, summary, severity, tags, entity,
                       first_seen, last_seen, event_count, evidence, assessment_id, source, created_at,
                       updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (f["dedup_key"], f["rule"], f["title"], f["summary"], f["severity"], json.dumps(f["tags"]),
                     f["entity"], f["first_seen"], f["last_seen"], f["event_count"], json.dumps(f["evidence"]),
                     f.get("assessment_id"), "detection", _now(), _now()))
                _note(conn, cur.lastrowid, "BlueWatch", "opened",
                      f"Found automatically by the “{f.get('rule_name', f['rule'])}” check.")
                new += 1
            elif row["event_count"] != f["event_count"]:
                conn.execute("""UPDATE incidents SET summary=?, last_seen=?, event_count=?, evidence=?,
                                updated_at=? WHERE id=?""",
                             (f["summary"], f["last_seen"], f["event_count"], json.dumps(f["evidence"]),
                              _now(), row["id"]))
                updated += 1
    return new, updated


def create_manual(title, summary, severity, author, tags=(), assessment_id=None, entity=None):
    if not title or not isinstance(title, str) or len(title) > 200:
        raise IncidentError("title is required (max 200 characters)")
    if severity not in SEVERITIES:
        raise IncidentError(f"severity must be one of {list(SEVERITIES)}")
    if not isinstance(summary, str) or len(summary) > 2000:
        raise IncidentError("summary must be text (max 2000 characters)")
    tags = _clean_tags(tags)
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO incidents (dedup_key, rule, title, summary, severity, tags, entity, first_seen,
               last_seen, event_count, evidence, assessment_id, source, created_at, updated_at)
               VALUES (NULL,'manual',?,?,?,?,?,?,?,0,'[]',?,'manual',?,?)""",
            (title, summary, severity, json.dumps(tags), entity, _now()[:19].replace("T", " "),
             _now()[:19].replace("T", " "), assessment_id, _now(), _now()))
        _note(conn, cur.lastrowid, author, "opened", "Opened by hand.")
        return cur.lastrowid


def _clean_tags(tags):
    out = []
    for t in tags or []:
        if not isinstance(t, str):
            raise IncidentError("tags must be text")
        t = re.sub(r"[^a-z0-9-]", "", t.strip().lower().replace(" ", "-"))[:40]
        if t and t not in out:
            out.append(t)
    return out


def list_incidents(status=None, severity=None, tag=None, assignee=None):
    q, args = "SELECT * FROM incidents WHERE 1=1", []
    if status:
        q += " AND status = ?"; args.append(status)
    if severity:
        q += " AND severity = ?"; args.append(severity)
    if assignee:
        q += " AND assignee IS ?" if assignee == "unassigned" else " AND assignee = ?"
        args.append(None if assignee == "unassigned" else assignee)
    q += " ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END, " \
         "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, last_seen DESC"
    with connect() as conn:
        rows = [_row(r) for r in conn.execute(q, args)]
    return [r for r in rows if not tag or tag in r["tags"]]


def get(incident_id):
    with connect() as conn:
        r = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if r is None:
            raise LookupError(f"incident {incident_id} not found")
        d = _row(r)
        d["notes"] = [dict(n) for n in conn.execute(
            "SELECT at, author, kind, text FROM incident_notes WHERE incident_id = ? ORDER BY id", (incident_id,))]
    return d


def update(incident_id, author, status=None, assignee=None, add_tag=None, remove_tag=None,
           severity=None):
    changes = []
    current = get(incident_id)
    with connect() as conn:
        if status is not None:
            if status not in STATUSES:
                raise IncidentError(f"status must be one of {list(STATUSES)}")
            if status != current["status"]:
                conn.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
                changes.append(("status", f"Status changed to {STATUSES[status]}."))
        if assignee is not None:
            assignee = assignee.strip()[:60] or None
            if assignee != current["assignee"]:
                conn.execute("UPDATE incidents SET assignee=? WHERE id=?", (assignee, incident_id))
                changes.append(("assign", f"Assigned to {assignee}." if assignee else "Unassigned."))
        if severity is not None:
            if severity not in SEVERITIES:
                raise IncidentError(f"severity must be one of {list(SEVERITIES)}")
            if severity != current["severity"]:
                conn.execute("UPDATE incidents SET severity=? WHERE id=?", (severity, incident_id))
                changes.append(("severity", f"Severity changed to {severity}."))
        tags = list(current["tags"])
        for t in _clean_tags([add_tag] if add_tag else []):
            if t not in tags:
                tags.append(t); changes.append(("tag", f"Tagged “{t}”."))
        for t in _clean_tags([remove_tag] if remove_tag else []):
            if t in tags:
                tags.remove(t); changes.append(("tag", f"Removed tag “{t}”."))
        if tags != current["tags"]:
            conn.execute("UPDATE incidents SET tags=? WHERE id=?", (json.dumps(tags), incident_id))
        for kind, text in changes:
            _note(conn, incident_id, author, kind, text)
        if changes:
            conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (_now(), incident_id))
    return [t for _, t in changes]


def add_note(incident_id, author, text):
    if not isinstance(text, str) or not text.strip() or len(text) > 2000:
        raise IncidentError("note must be 1-2000 characters")
    get(incident_id)
    with connect() as conn:
        _note(conn, incident_id, author, "note", text.strip())


def summary():
    with connect() as conn:
        by_status = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) n FROM incidents GROUP BY status")}
        open_by_sev = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) n FROM incidents WHERE status IN ('new','investigating') GROUP BY severity")}
        unassigned = conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('new','investigating') "
                                  "AND assignee IS NULL").fetchone()[0]
    return {"by_status": {k: by_status.get(k, 0) for k in STATUSES},
            "open_by_severity": {k: open_by_sev.get(k, 0) for k in SEVERITIES},
            "open": by_status.get("new", 0) + by_status.get("investigating", 0),
            "unassigned_open": unassigned}
