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
    return jsonify({
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
        "incidents": incidents.summary(),
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


@bp.route("/api/soc/team")
def team_list():
    return jsonify({"team": team(), "tags": incidents.SUGGESTED_TAGS, "statuses": incidents.STATUSES})


@bp.route("/api/soc/incidents", methods=["GET"])
def list_incidents():
    a = request.args
    return jsonify(incidents.list_incidents(a.get("status") or None, a.get("severity") or None,
                                            a.get("tag") or None, a.get("assignee") or None))


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
