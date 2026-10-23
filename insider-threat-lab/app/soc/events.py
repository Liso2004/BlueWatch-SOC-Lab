"""
Read the SecureBank / BlueWatch security log (the same file Logstash sends to Elasticsearch)
and turn each line into a structured event with a plain-English name.
"""

import os
import re
from datetime import datetime

LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - (\w+) - ([A-Z_]+): (.*) - USER:(\S*) - IP:(\S*)\s*$")

# Event codes as written by the apps -> plain names and the dashboard category they count under.
PLAIN = {
    "LOGIN_SUCCESS": ("Signed in", "access"),
    "LOGIN_FAILED": ("Failed sign-in", "attack"),
    "DASHBOARD_ACCESS": ("Opened the staff app", "access"),
    "LOGOUT": ("Signed out", "access"),
    "DATABASE_QUERY": ("Viewed customer list", "data"),
    "SEARCH_QUERY": ("Searched customers", "data"),
    "MOBILE_RISK_ASSESSMENT": ("Checked an Android app", "mobile"),
    "MOBILE_RISK_FEEDBACK": ("Recorded analyst decision", "mobile"),
    "MOBILE_RISK_LABEL_EXPORT": ("Exported training labels", "mobile"),
    "GENAI_CASE_BRIEF": ("Wrote AI case brief", "mobile"),
    "VULN_CONTEXT_LOOKUP": ("Looked up phone vulnerabilities", "mobile"),
    "API_AUTH_FAILED": ("Rejected API key", "attack"),
    "INCIDENT_UPDATED": ("Updated an incident", "soc"),
    "INCIDENT_CREATED": ("Opened an incident", "soc"),
}


def log_path():
    return os.getenv("APP_LOG_FILE", "/var/log/app/banking_app.log")


def _int(pattern, text):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def parse_line(line):
    m = LINE.match(line)
    if not m:
        return None
    ts, level, code, details, user, ip = m.groups()
    name, category = PLAIN.get(code, (code.replace("_", " ").capitalize(), "other"))
    ev = {"time": ts, "level": level, "code": code, "name": name, "category": category,
          "details": details, "user": user, "ip": ip}
    if code in ("DATABASE_QUERY", "SEARCH_QUERY"):
        ev["records"] = _int(r"(?:Rows|Results): (\d+)", details) or 0
        term = re.search(r'Search: "(.*?)"', details)
        if term:
            ev["search_term"] = term.group(1)
    elif code == "LOGIN_FAILED":
        target = re.search(r"Failed login attempt for (\S+)", details)
        ev["target_account"] = target.group(1) if target else user
    elif code == "MOBILE_RISK_ASSESSMENT":
        for key, pat in (("assessment_id", r"Assessment: ([\w-]+)"), ("sample_id", r"Sample: (\S+)"),
                         ("verdict", r"Verdict: (\w+)"), ("score", r"Score: ([\d.]+)")):
            m2 = re.search(pat, details)
            if m2:
                ev[key] = float(m2.group(1)) if key == "score" else m2.group(1)
    return ev


def read_events(path=None):
    path = path or log_path()
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        events = [e for e in (parse_line(line) for line in f) if e]
    events.sort(key=lambda e: e["time"])
    return events


def to_dt(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
