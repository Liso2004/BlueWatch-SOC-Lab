"""
Detection rules: turn raw security events into findings a SOC analyst can act on.
Each finding is written in plain language and carries the evidence lines it came from.
Thresholds are deliberately simple and visible so the team can tune them.
"""

from collections import defaultdict

from .events import to_dt

FAILED_LOGIN_BURST = 5          # failed sign-ins on one account ...
FAILED_LOGIN_GAP_MIN = 15       # ... with no more than 15 minutes between attempts
BULK_RECORDS_PER_HOUR = 200     # customer records viewed by one person in one hour
BROAD_SEARCH_RESULTS = 100      # a single search returning this many customers
API_FAIL_BURST = 3              # rejected API keys within 10 minutes

RULES = {
    "failed_logins": {"name": "Repeated failed sign-ins", "tags": ["credential-attack"]},
    "bulk_data": {"name": "Large amount of customer data viewed", "tags": ["insider-threat", "data-exfiltration"]},
    "broad_search": {"name": "Very broad customer search", "tags": ["insider-threat"]},
    "risky_app": {"name": "Risky Android app found", "tags": ["mobile-malware"]},
    "api_abuse": {"name": "Repeated rejected API keys", "tags": ["api-abuse"]},
}


def _bursts(events, gap_minutes):
    """Split time-ordered events into runs where consecutive events are within gap_minutes."""
    run = []
    for e in events:
        if run and (to_dt(e["time"]) - to_dt(run[-1]["time"])).total_seconds() > gap_minutes * 60:
            yield run
            run = []
        run.append(e)
    if run:
        yield run


def _evidence(events, limit=15):
    return [f"{e['time']}  {e['name']}  ·  user {e['user']}  ·  IP {e['ip']}  ·  {e['details']}"
            for e in events[:limit]]


def _finding(rule, key, title, summary, severity, events, entity, **extra):
    return {"rule": rule, "rule_name": RULES[rule]["name"], "dedup_key": f"{rule}:{key}", "title": title,
            "summary": summary,
            "severity": severity, "entity": entity, "first_seen": events[0]["time"],
            "last_seen": events[-1]["time"], "event_count": len(events),
            "evidence": _evidence(events), "tags": list(RULES[rule]["tags"]), **extra}


def failed_logins(events):
    by_account = defaultdict(list)
    for e in events:
        if e["code"] == "LOGIN_FAILED":
            by_account[e["target_account"]].append(e)
    for account, evs in by_account.items():
        for run in _bursts(evs, FAILED_LOGIN_GAP_MIN):
            if len(run) >= FAILED_LOGIN_BURST:
                ips = sorted({e["ip"] for e in run})
                yield _finding(
                    "failed_logins", f"{account}:{run[0]['time']}",
                    f"Repeated failed sign-ins on account “{account}”",
                    f"{len(run)} failed sign-in attempts on the “{account}” account between {run[0]['time']} "
                    f"and {run[-1]['time']}, from {', '.join(ips)}. This pattern looks like someone "
                    f"guessing the password.",
                    "high" if len(run) >= 10 else "medium", run, account)


def bulk_data(events):
    by_user_hour = defaultdict(list)
    for e in events:
        if e["code"] in ("DATABASE_QUERY", "SEARCH_QUERY") and e["user"] not in ("anonymous", "-"):
            by_user_hour[(e["user"], e["time"][:13])].append(e)
    for (user, hour), evs in by_user_hour.items():
        total = sum(e.get("records", 0) for e in evs)
        if total >= BULK_RECORDS_PER_HOUR:
            yield _finding(
                "bulk_data", f"{user}:{hour}",
                f"Large amount of customer data viewed by “{user}”",
                f"{user} viewed {total:,} customer records in {len(evs)} requests between {evs[0]['time']} "
                f"and {evs[-1]['time']}. The alert level is {BULK_RECORDS_PER_HOUR} records in one hour — "
                f"check whether this was part of their job or an insider copying customer data.",
                "high" if total >= 2 * BULK_RECORDS_PER_HOUR else "medium", evs, user, records=total)


def broad_search(events):
    by_user_day = defaultdict(list)
    for e in events:
        if e["code"] == "SEARCH_QUERY" and e.get("records", 0) >= BROAD_SEARCH_RESULTS:
            by_user_day[(e["user"], e["time"][:10])].append(e)
    for (user, day), evs in by_user_day.items():
        biggest = max(evs, key=lambda e: e["records"])
        yield _finding(
            "broad_search", f"{user}:{day}",
            f"Very broad customer search by “{user}”",
            f"{user} ran {len(evs)} search(es) on {day} that each returned {BROAD_SEARCH_RESULTS}+ customers "
            f"(largest: “{biggest.get('search_term', '')}” → {biggest['records']} records). Broad searches can "
            f"be a way to pull many customer records at once.",
            "medium", evs, user)


def risky_apps(events):
    by_app_day = defaultdict(list)
    for e in events:
        if e["code"] == "MOBILE_RISK_ASSESSMENT" and e.get("verdict") == "flag_for_review":
            by_app_day[(e.get("sample_id", "adhoc"), e["time"][:10])].append(e)
    for (app, day), evs in by_app_day.items():
        score = max(e.get("score", 0) for e in evs)
        yield _finding(
            "risky_app", f"{app}:{day}",
            f"Risky Android app found: {app}",
            f"BlueWatch Mobile marked the Android app “{app}” as needing a look (highest risk score "
            f"{score} out of 1). Check which customers have it installed and where it came from. "
            f"The score is a prompt to investigate, not proof of malware.",
            "high" if score >= 0.9 else "medium", evs, app,
            assessment_id=evs[-1].get("assessment_id"))


def api_abuse(events):
    evs = [e for e in events if e["code"] == "API_AUTH_FAILED"]
    for run in _bursts(evs, 10):
        if len(run) >= API_FAIL_BURST:
            yield _finding(
                "api_abuse", f"{run[0]['ip']}:{run[0]['time']}",
                "Repeated rejected API keys",
                f"{len(run)} API calls with a missing or wrong key between {run[0]['time']} and "
                f"{run[-1]['time']} from {run[0]['ip']}. Someone may be trying to use the bank API without "
                f"permission.", "medium", run, run[0]["ip"])


def run_all(events):
    for rule in (failed_logins, bulk_data, broad_search, risky_apps, api_abuse):
        yield from rule(events)
