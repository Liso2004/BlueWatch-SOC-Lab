"""
BlueWatch Security Console: SIEM-style overview, incidents (tags, assignees, status, notes) and
the security tools (Android App Risk). Built on the SecureBank security log.
"""

import os
from collections import Counter, defaultdict

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

import mobile_risk
from mobile_risk import store as risk_store

from . import detections, events, incidents

bp = Blueprint("soc", __name__)

WARN_RECORDS = 50  # one request returning this many customer records counts as a warning sign


def team():
    return [t.strip() for t in os.getenv("SOC_TEAM", "analyst,jdoe,admin,Liso,Stacey-Lee").split(",") if t.strip()]


def _log(code, details):
    current_app.logger.info(f"{code}: {details}", extra={"user": session.get("username", "anonymous"),
                                                         "ip": request.remote_addr})


@bp.before_request
def require_login():
    if "username" not in session:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/login")


# --- pages ---------------------------------------------------------------------------------

@bp.route("/security")
def overview_page():
    return render_template("console_overview.html", username=session["username"], active="overview")


@bp.route("/security/incidents")
def incidents_page():
    return render_template("console_incidents.html", username=session["username"], active="incidents",
                           team=team(), statuses=incidents.STATUSES, tags=incidents.SUGGESTED_TAGS)


# --- data ----------------------------------------------------------------------------------

def run_detections():
    return incidents.sync(list(detections.run_all(events.read_events())))


@bp.route("/api/soc/sync", methods=["POST"])
def sync():
    new, updated = run_detections()
    if new:
        _log("INCIDENT_CREATED", f"Detections opened {new} new incident(s)")
    return jsonify({"new": new, "updated": updated})


@bp.route("/api/soc/overview")
def overview():
    evs = events.read_events()
    per_day = defaultdict(Counter)
    for e in evs:
        per_day[e["time"][:10]][e["category"]] += 1
    records = Counter()
    for e in evs:
        if e["code"] in ("DATABASE_QUERY", "SEARCH_QUERY") and e["user"] not in ("anonymous", "-"):
            records[e["user"]] += e.get("records", 0)
    failed = Counter(e["target_account"] for e in evs if e["code"] == "LOGIN_FAILED")
    types = Counter(e["name"] for e in evs)
    apps = [e for e in evs if e["code"] == "MOBILE_RISK_ASSESSMENT"]
    splits = mobile_risk.get_model().metrics["splits"]
    all_inc = incidents.list_incidents()
    warning = [e for e in evs if e["code"] in ("LOGIN_FAILED", "API_AUTH_FAILED")
               or (e["code"] in ("DATABASE_QUERY", "SEARCH_QUERY") and e.get("records", 0) >= WARN_RECORDS)
               or (e["code"] == "MOBILE_RISK_ASSESSMENT" and e.get("verdict") == "flag_for_review")]
    funnel = [
        {"stage": "Security events", "value": len(evs), "explain": "Everything the bank's systems recorded"},
        {"stage": "Warning signs", "value": len(warning),
         "explain": f"Failed sign-ins, rejected API keys, {WARN_RECORDS}+ records viewed at once, risky apps"},
        {"stage": "Incidents opened", "value": len(all_inc), "explain": "Warning signs grouped into cases"},
        {"stage": "Being handled", "value": sum(1 for i in all_inc if i["assignee"] or i["status"] != "new"),
         "explain": "Assigned to someone or already worked on"},
        {"stage": "Closed", "value": sum(1 for i in all_inc if i["status"] in ("resolved", "false_positive")),
         "explain": "Resolved or marked as a false alarm"},
    ]
    insight = None
    total_records = sum(records.values())
    if records and total_records:
        who, n = records.most_common(1)[0]
        insight = {"headline": f"{round(100 * n / total_records)}%",
                   "title": f"of all customer records were viewed by one account: {who}",
                   "detail": f"{who} viewed {n:,} of {total_records:,} customer records. Check whether that "
                             f"matches their job — this is the pattern of an insider copying data.",
                   "account": who}
    failed_days = Counter(e["time"][:10] for e in evs if e["code"] == "LOGIN_FAILED")
    by_hour = [{"hour": h, "attack": 0, "data": 0} for h in range(24)]
    for e in warning:
        bucket = "attack" if e["code"] in ("LOGIN_FAILED", "API_AUTH_FAILED") else "data" if e["category"] == "data" else None
        if bucket:
            by_hour[int(e["time"][11:13])][bucket] += 1
    summ = incidents.summary()
    by_type = sorted(((detections.RULES.get(r, {"name": "Opened by hand"})["name"], n)
                      for r, n in summ["open_by_rule"].items()), key=lambda x: -x[1])
    return jsonify({
        "funnel": funnel,
        "by_hour": by_hour,
        "open_by_type": by_type,
        "workload": incidents.workload(team()),
        "insight": insight,
        "failed_by_day": sorted(failed_days.items())[-14:],
        "app_checks": [{"time": e["time"], "app": e.get("sample_id"), "flagged": e.get("verdict") == "flag_for_review",
                        "score": e.get("score")} for e in apps][-40:],
        "range": [evs[0]["time"], evs[-1]["time"]] if evs else None,
        "totals": {
            "events": len(evs),
            "failed_signins": sum(failed.values()),
            "records_viewed": sum(records.values()),
            "people": len({e["user"] for e in evs if e["user"] not in ("anonymous", "-")}),
            "apps_checked": len(apps),
            "apps_flagged": sum(1 for e in apps if e.get("verdict") == "flag_for_review"),
        },
        "per_day": [{"day": d, **per_day[d]} for d in sorted(per_day)][-14:],
        "records_by_person": records.most_common(8),
        "failed_by_account": failed.most_common(8),
        "event_types": types.most_common(12),
        "recent": [{k: e.get(k) for k in ("time", "name", "category", "user", "ip", "details")}
                   for e in evs[-25:][::-1]],
        "incidents": summ,
        "model": {
            "alarm_accuracy": splits["A_random_stratified"]["precision"],
            "malware_caught": splits["A_random_stratified"]["recall"],
            "new_families_caught": splits["C_unseen_malware_families"]["recall"],
            "behaviour_only_caught": splits.get("D_runtime_behaviour_only", {}).get("recall"),
            "newer_app_false_alarms": splits["B_per_class_temporal"]["false_positive_rate"],
            "test_apps": splits["A_random_stratified"]["test_size"],
        },
        "decisions": risk_store.summary(),
    })


@bp.route("/api/soc/events")
def search_events():
    """Search the security log: every word must appear in the event (name, details, user or IP)."""
    words = [w.lower() for w in request.args.get("q", "").split() if w][:8]
    if not words:
        return jsonify({"error": "type something to search for"}), 422
    hits = []
    for e in reversed(events.read_events()):
        hay = f"{e['name']} {e['code']} {e['details']} {e['user']} {e['ip']} {e['time']}".lower()
        if all(w in hay for w in words):
            hits.append({k: e.get(k) for k in ("time", "name", "category", "user", "ip", "details")})
            if len(hits) == 50:
                break
    return jsonify({"query": " ".join(words), "results": hits})


@bp.route("/api/soc/team")
def team_list():
    return jsonify({"team": team(), "tags": incidents.SUGGESTED_TAGS, "statuses": incidents.STATUSES,
                    "workload": incidents.workload(team())})


@bp.route("/api/soc/incidents", methods=["GET"])
def list_incidents():
    a = request.args
    rows = incidents.list_incidents(a.get("status") or None, a.get("severity") or None,
                                    a.get("tag") or None, a.get("assignee") or None)
    if a.get("involving"):
        person = session["username"] if a["involving"] == "me" else a["involving"]
        ids = incidents.involving(person)
        rows = [r for r in rows if r["id"] in ids]
    if a.get("review") == "waiting":
        rows = [r for r in rows if r.get("review_status") == "requested"]
    return jsonify(rows)


@bp.route("/api/soc/incidents", methods=["POST"])
def create_incident():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    try:
        iid = incidents.create_manual(body.get("title"), body.get("summary", ""), body.get("severity", "medium"),
                                      session["username"], body.get("tags") or [], body.get("assessment_id"),
                                      body.get("entity"))
    except incidents.IncidentError as e:
        return jsonify({"error": str(e)}), 422
    _log("INCIDENT_CREATED", f"Incident: {iid} | Title: {body.get('title')}")
    return jsonify(incidents.get(iid)), 201


@bp.route("/api/soc/incidents/<int:iid>", methods=["GET"])
def get_incident(iid):
    try:
        return jsonify(incidents.get(iid))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404


@bp.route("/api/soc/incidents/<int:iid>", methods=["PATCH"])
def update_incident(iid):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    try:
        changes = incidents.update(iid, session["username"], body.get("status"), body.get("assignee"),
                                   body.get("add_tag"), body.get("remove_tag"), body.get("severity"))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except incidents.IncidentError as e:
        return jsonify({"error": str(e)}), 422
    if changes:
        _log("INCIDENT_UPDATED", f"Incident: {iid} | " + " ".join(changes))
    return jsonify({"changes": changes, "incident": incidents.get(iid)})


@bp.route("/api/soc/incidents/<int:iid>/notes", methods=["POST"])
def add_note(iid):
    body = request.get_json(silent=True) or {}
    try:
        incidents.add_note(iid, session["username"], body.get("text"))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except incidents.IncidentError as e:
        return jsonify({"error": str(e)}), 422
    _log("INCIDENT_UPDATED", f"Incident: {iid} | Note added")
    return jsonify(incidents.get(iid)), 201


@bp.route("/api/soc/incidents/<int:iid>/suggest-reviewer", methods=["GET"])
def suggest_reviewer(iid):
    try:
        return jsonify(incidents.suggest_reviewer(iid, team(), session["username"]))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404


@bp.route("/api/soc/incidents/<int:iid>/review", methods=["POST"])
def review(iid):
    body = request.get_json(silent=True) or {}
    try:
        changes = incidents.set_review(iid, session["username"], body.get("reviewer"), body.get("action"))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except incidents.IncidentError as e:
        return jsonify({"error": str(e)}), 422
    if changes:
        _log("INCIDENT_UPDATED", f"Incident: {iid} | " + " ".join(changes))
    return jsonify({"changes": changes, "incident": incidents.get(iid)})


@bp.route("/api/soc/incidents/<int:iid>/tasks", methods=["POST"])
def add_task(iid):
    body = request.get_json(silent=True) or {}
    try:
        incidents.add_task(iid, session["username"], body.get("assignee"), body.get("text"))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except incidents.IncidentError as e:
        return jsonify({"error": str(e)}), 422
    _log("INCIDENT_UPDATED", f"Incident: {iid} | Task for {body.get('assignee')}")
    return jsonify(incidents.get(iid)), 201


@bp.route("/api/soc/incidents/<int:iid>/tasks/<int:tid>", methods=["PATCH"])
def update_task(iid, tid):
    body = request.get_json(silent=True) or {}
    try:
        incidents.set_task_done(iid, tid, session["username"], bool(body.get("done")))
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    _log("INCIDENT_UPDATED", f"Incident: {iid} | Task {tid} {'done' if body.get('done') else 'reopened'}")
    return jsonify(incidents.get(iid))
