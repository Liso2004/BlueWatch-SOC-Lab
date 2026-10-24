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
CREATE TABLE IF NOT EXISTS incident_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    assignee TEXT NOT NULL,
    text TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    done_at TEXT
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


REVIEW_STATES = {"requested": "Waiting for review", "approved": "Review approved",
                 "changes_requested": "Sent back by reviewer"}


def connect():
    conn = store.connect()
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
    for col in ("reviewer", "review_status"):  # added after the first release
        if col not in cols:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")
    return conn


def _row(r):
    d = dict(r)
    d["tags"] = json.loads(d["tags"])
    d["evidence"] = json.loads(d["evidence"])
    d["status_label"] = STATUSES.get(d["status"], d["status"])
    d["review_label"] = REVIEW_STATES.get(d.get("review_status")) if d.get("review_status") else None
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
        d["tasks"] = [dict(t) for t in conn.execute(
            "SELECT id, assignee, text, done, created_by, created_at, done_at FROM incident_tasks "
            "WHERE incident_id = ? ORDER BY done, id", (incident_id,))]
    return d


def update(incident_id, author, status=None, assignee=None, add_tag=None, remove_tag=None,
           severity=None):
    changes = []
    current = get(incident_id)
    if assignee and current["entity"] and assignee.strip() == current["entity"]:
        raise IncidentError("nobody can handle an incident about themselves")
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
        waiting_review = conn.execute("SELECT COUNT(*) FROM incidents WHERE review_status = 'requested'").fetchone()[0]
        by_rule = {r["rule"]: r["n"] for r in conn.execute(
            "SELECT rule, COUNT(*) n FROM incidents WHERE status IN ('new','investigating') GROUP BY rule")}
    return {"by_status": {k: by_status.get(k, 0) for k in STATUSES},
            "open_by_severity": {k: open_by_sev.get(k, 0) for k in SEVERITIES},
            "open": by_status.get("new", 0) + by_status.get("investigating", 0),
            "unassigned_open": unassigned, "waiting_review": waiting_review, "open_by_rule": by_rule}


# --- reviewers and tasks -------------------------------------------------------------------

def workload(team):
    """Open work per person: incidents assigned, reviews waiting on them, open tasks."""
    with connect() as conn:
        assigned = dict(conn.execute("SELECT assignee, COUNT(*) FROM incidents WHERE status IN "
                                     "('new','investigating') AND assignee IS NOT NULL GROUP BY assignee").fetchall())
        reviews = dict(conn.execute("SELECT reviewer, COUNT(*) FROM incidents WHERE review_status = 'requested' "
                                    "AND reviewer IS NOT NULL GROUP BY reviewer").fetchall())
        tasks = dict(conn.execute("SELECT assignee, COUNT(*) FROM incident_tasks WHERE done = 0 "
                                  "GROUP BY assignee").fetchall())
    people = list(dict.fromkeys(list(team) + list(assigned) + list(reviews) + list(tasks)))
    return [{"name": p, "assigned": assigned.get(p, 0), "reviews": reviews.get(p, 0), "tasks": tasks.get(p, 0)}
            for p in people]


def suggest_reviewer(incident_id, team, requested_by):
    """Someone not already on the incident (and not the person it is about), with the fewest pending
    reviews, then the least open work."""
    inc = get(incident_id)
    busy = {inc["assignee"], requested_by, inc["entity"]} | {t["assignee"] for t in inc["tasks"] if not t["done"]}
    load = {w["name"]: w for w in workload(team)}
    candidates = [load.get(p, {"name": p, "assigned": 0, "reviews": 0, "tasks": 0}) for p in team if p not in busy]
    if not candidates:
        return {"suggested": None, "reason": "Everyone on the team is already working on this incident.",
                "candidates": []}
    candidates.sort(key=lambda w: (w["reviews"], w["assigned"] + w["tasks"]))
    best = candidates[0]
    return {"suggested": best["name"], "candidates": candidates,
            "reason": f"{best['name']} is not working on this incident and has the lightest load: "
                      f"{best['reviews']} review(s) waiting, {best['assigned']} open incident(s), "
                      f"{best['tasks']} open task(s)."}


def set_review(incident_id, author, reviewer=None, action=None):
    """action: request | approve | send_back. Only the named reviewer may approve or send back."""
    inc = get(incident_id)
    changes = []
    with connect() as conn:
        if reviewer is not None:
            reviewer = reviewer.strip()[:60] or None
            if reviewer and reviewer == inc["assignee"]:
                raise IncidentError("the reviewer must be someone other than the person handling it")
            if reviewer and reviewer == inc["entity"]:
                raise IncidentError("nobody can review an incident about themselves")
            if reviewer != inc["reviewer"]:
                conn.execute("UPDATE incidents SET reviewer=?, review_status=NULL WHERE id=?", (reviewer, incident_id))
                changes.append(("review", f"Reviewer set to {reviewer}." if reviewer else "Reviewer removed."))
                inc["reviewer"] = reviewer
        if action:
            if action not in ("request", "approve", "send_back"):
                raise IncidentError("action must be request, approve or send_back")
            if not inc["reviewer"]:
                raise IncidentError("choose a reviewer first")
            if action in ("approve", "send_back") and author != inc["reviewer"]:
                raise PermissionError(f"only the reviewer ({inc['reviewer']}) can do that")
            state = {"request": "requested", "approve": "approved", "send_back": "changes_requested"}[action]
            conn.execute("UPDATE incidents SET review_status=? WHERE id=?", (state, incident_id))
            changes.append(("review", {"request": f"Asked {inc['reviewer']} to review.",
                                       "approve": "Review approved.",
                                       "send_back": "Reviewer sent it back for more work."}[action]))
        for kind, text in changes:
            _note(conn, incident_id, author, kind, text)
        if changes:
            conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (_now(), incident_id))
    return [t for _, t in changes]


def add_task(incident_id, author, assignee, text):
    if not isinstance(assignee, str) or not assignee.strip() or len(assignee) > 60:
        raise IncidentError("choose who should do this")
    if not isinstance(text, str) or not text.strip() or len(text) > 300:
        raise IncidentError("describe the task (1-300 characters)")
    get(incident_id)
    with connect() as conn:
        conn.execute("INSERT INTO incident_tasks (incident_id, assignee, text, created_by, created_at) "
                     "VALUES (?,?,?,?,?)", (incident_id, assignee.strip(), text.strip(), author, _now()))
        _note(conn, incident_id, author, "task", f"Asked {assignee.strip()} to: {text.strip()}")


def set_task_done(incident_id, task_id, author, done):
    with connect() as conn:
        t = conn.execute("SELECT assignee, text FROM incident_tasks WHERE id=? AND incident_id=?",
                         (task_id, incident_id)).fetchone()
        if t is None:
            raise LookupError(f"task {task_id} not found")
        conn.execute("UPDATE incident_tasks SET done=?, done_at=? WHERE id=?",
                     (1 if done else 0, _now() if done else None, task_id))
        _note(conn, incident_id, author, "task",
              f"{'Completed' if done else 'Reopened'} task for {t['assignee']}: {t['text']}")


def involving(person):
    """Incident ids where the person is assignee, reviewer, or has an open task."""
    with connect() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM incidents WHERE assignee=? OR reviewer=?", (person, person))}
        ids |= {r[0] for r in conn.execute(
            "SELECT incident_id FROM incident_tasks WHERE assignee=? AND done=0", (person,))}
    return ids
