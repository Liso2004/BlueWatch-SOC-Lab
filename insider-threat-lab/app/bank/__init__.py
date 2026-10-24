"""
Simulated SecureBank ledger for the demo. Money moves between accounts so the bank feels live,
and a deterministic fraud engine flags suspicious payments with explicit reasons — correlating a
BlueWatch-flagged Android app on the customer's device with an anomalous outbound transfer, and
adding Android CVE context from the cached NVD data.

Everything here is synthetic demo data in SQLite (no real money, no real customers). The "flagging"
is rules + the existing ML app-risk signal + NVD context, shown with its reasons; it is decision
support, not an automated block.
"""

import json
import os
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, session

from mobile_risk import store

bp = Blueprint("bank", __name__)

# Fixed, deterministic set of demo accounts (name, starting balance, Android version on their phone).
SEED_ACCOUNTS = [
    ("Ian Walker", 42150.00, "13.0"), ("Diana Evans", 88200.50, "14.0"), ("Julia Hall", 15380.75, "12.0"),
    ("George Clark", 67540.00, "13.0"), ("Fiona Brown", 9120.40, "11.0"), ("Charlie Davis", 51880.00, "15.0"),
    ("Hannah Lewis", 73410.90, "13.0"), ("Alice Johnson", 24110.00, "14.0"), ("Bob Smith", 5640.15, "12.0"),
    ("SecureBank Payroll", 500000.00, None), ("City Water & Lights", 0.00, None), ("QuickCart Stores", 0.00, None),
]
NORMAL_KINDS = ["Salary", "Groceries", "Transfer to friend", "Utilities", "Online purchase", "Rent"]
HIGH_VALUE = 20000.0           # a single payment at or above this is "high value"
NVD_CACHE = Path(os.getenv("NVD_CACHE_DIR", "/var/cache/bluewatch-nvd"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS bank_accounts (
    acct TEXT PRIMARY KEY, name TEXT NOT NULL, balance REAL NOT NULL,
    android_version TEXT, device_risk REAL, device_note TEXT, risk_assessment_id TEXT
);
CREATE TABLE IF NOT EXISTS bank_txns (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, from_acct TEXT, to_acct TEXT,
    from_name TEXT, to_name TEXT, amount REAL NOT NULL, kind TEXT NOT NULL,
    flagged INTEGER NOT NULL DEFAULT 0, reason TEXT, scenario TEXT
);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    conn = store.connect()
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM bank_accounts").fetchone()[0] == 0:
        rng = random.Random(42)
        for name, bal, ver in SEED_ACCOUNTS:
            conn.execute("INSERT INTO bank_accounts (acct, name, balance, android_version) VALUES (?,?,?,?)",
                         (f"62{rng.randint(10**9, 10**10 - 1)}", name, bal, ver))
    return conn


def _accounts(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM bank_accounts ORDER BY name")]


def cve_context(version):
    """Android CVE counts for a version from the NVD cache only (never triggers a live fetch)."""
    f = NVD_CACHE / f"android-{version}.json"
    if not version or not f.exists():
        return None
    try:
        matched = json.loads(f.read_text())["matched"]
    except (ValueError, KeyError, OSError):
        return None
    sev = {}
    for m in matched:
        if m.get("match_confidence") != "unspecified":
            s = (m.get("cvss") or {}).get("severity") or "NONE"
            sev[s] = sev.get(s, 0) + 1
    return {"version": version, "critical": sev.get("CRITICAL", 0), "high": sev.get("HIGH", 0),
            "total": sum(sev.values())}


def _record(conn, frm, to, amount, kind, flagged=0, reason=None, scenario=None):
    conn.execute("""INSERT INTO bank_txns (at, from_acct, to_acct, from_name, to_name, amount, kind,
                    flagged, reason, scenario) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                 (_now(), frm["acct"], to["acct"], frm["name"], to["name"], round(amount, 2), kind,
                  flagged, reason, scenario))
    conn.execute("UPDATE bank_accounts SET balance = balance - ? WHERE acct = ?", (amount, frm["acct"]))
    conn.execute("UPDATE bank_accounts SET balance = balance + ? WHERE acct = ?", (amount, to["acct"]))


def _log(code, details):
    current_app.logger.info(f"{code}: {details}", extra={"user": session.get("username", "system"),
                                                         "ip": request.remote_addr if request else "-"})


def assess_payment(frm, amount, kind):
    """Deterministic fraud check. Returns (flagged, reason). The headline signal is a high-value
    transfer from an account whose device was flagged by BlueWatch; CVE context is added, not used
    as proof."""
    reasons = []
    flagged = False
    if frm.get("device_risk") and amount >= HIGH_VALUE:
        flagged = True
        reasons.append(f"high-value payment of R{amount:,.0f} from an account whose phone BlueWatch "
                       f"flagged (risk {frm['device_risk']:.2f}: {frm.get('device_note') or 'risky app'})")
        ctx = cve_context(frm.get("android_version"))
        if ctx and ctx["critical"]:
            reasons.append(f"the phone runs Android {ctx['version']}, which has {ctx['critical']} known "
                           f"critical vulnerabilities (NVD)")
    elif amount >= 2 * HIGH_VALUE:
        flagged = True
        reasons.append(f"unusually large payment of R{amount:,.0f}")
    if flagged:
        reasons.append("review before release — do not block the customer on this alone")
    if not reasons:
        return flagged, None
    text = "; ".join(reasons)
    return flagged, text[0].upper() + text[1:]


def simulate(n=6):
    """Generate n normal payments (money flowing), applying the fraud check to each."""
    created = flagged = 0
    with connect() as conn:
        accts = [a for a in _accounts(conn) if a["name"] not in ("SecureBank Payroll",)]
        payees = _accounts(conn)
        for _ in range(n):
            frm = random.choice(accts)
            to = random.choice([a for a in payees if a["acct"] != frm["acct"]])
            amount = round(random.uniform(120, 4500), 2)
            if frm["balance"] < amount:
                continue
            flag, reason = assess_payment(frm, amount, "payment")
            _record(conn, frm, to, amount, random.choice(NORMAL_KINDS), int(flag), reason)
            created += 1
            flagged += int(flag)
    if created:
        _log("BANK_ACTIVITY", f"Simulated {created} payment(s), {flagged} flagged")
    return {"created": created, "flagged": flagged}


def overview():
    with connect() as conn:
        accts = _accounts(conn)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM bank_txns ORDER BY id DESC LIMIT 25")]
        day = conn.execute("SELECT COUNT(*) c, COALESCE(SUM(amount),0) s FROM bank_txns WHERE at LIKE ?",
                           (today + "%",)).fetchone()
        flagged = conn.execute("SELECT COUNT(*) FROM bank_txns WHERE flagged = 1").fetchone()[0]
    return {"accounts": len([a for a in accts if not a["name"].startswith(("SecureBank", "City", "QuickCart"))]),
            "total_balance": sum(a["balance"] for a in accts),
            "today": {"count": day["c"], "moved": day["s"]}, "flagged": flagged, "recent": rows}


def mark_device_risk(name_fragment, risk, note, android_version=None, assessment_id=None):
    """Attach a BlueWatch app-risk result to a customer's account (the device is now suspect)."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM bank_accounts WHERE name LIKE ? ORDER BY balance DESC LIMIT 1",
                           (f"%{name_fragment}%",)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE bank_accounts SET device_risk=?, device_note=?, android_version=COALESCE(?, android_version), "
                     "risk_assessment_id=? WHERE acct=?", (risk, note, android_version, assessment_id, row["acct"]))
        return dict(conn.execute("SELECT * FROM bank_accounts WHERE acct=?", (row["acct"],)).fetchone())


def compromised_device_transfer(victim, mule_name="QuickCart Stores", amount=38500.0):
    """Simulate the money leaving a compromised customer's account right after the device was flagged.
    Returns the recorded transaction with its reasons, so the caller can open an incident."""
    with connect() as conn:
        v = conn.execute("SELECT * FROM bank_accounts WHERE acct=?", (victim["acct"],)).fetchone()
        mule = conn.execute("SELECT * FROM bank_accounts WHERE name LIKE ? LIMIT 1", (f"%{mule_name}%",)).fetchone()
        if v is None or mule is None:
            return None
        v, mule = dict(v), dict(mule)
        amount = min(amount, v["balance"])
        flag, reason = assess_payment(v, amount, "transfer")
        _record(conn, v, mule, amount, "Transfer to new payee", int(flag), reason, scenario="compromised-device")
        tx = dict(conn.execute("SELECT * FROM bank_txns ORDER BY id DESC LIMIT 1").fetchone())
    _log("BANK_FRAUD_FLAG", f"Flagged transfer R{amount:,.0f} from {v['name']} -> {mule['name']}")
    return {"tx": tx, "victim": v, "mule": mule, "reason": reason,
            "cve": cve_context(v.get("android_version"))}


# A crafted feature vector for a sideloaded-app scenario: the KronoDroid feature counts a
# banking-trojan-style app would show (overlay + accessibility + SMS + device admin + persistence).
# These are counts the detector consumes; this is not runnable app code.
SIDELOADED_FEATURES = {
    "SYSTEM_ALERT_WINDOW": 1, "BIND_ACCESSIBILITY_SERVICE": 1, "RECEIVE_SMS": 1, "READ_SMS": 1,
    "SEND_SMS": 1, "BIND_NOTIFICATION_LISTENER_SERVICE": 1, "RECEIVE_BOOT_COMPLETED": 1,
    "REQUEST_INSTALL_PACKAGES": 1, "READ_PHONE_STATE": 1, "READ_CONTACTS": 1, "INTERNET": 1,
    "dangerous": 11, "nr_permissions": 22, "total_perm": 24, "NrServices": 5, "NrIntReceiversActions": 6,
}


@bp.before_request
def require_login():
    from flask import redirect
    if "username" not in session:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/login")


@bp.route("/api/bank/overview")
def bank_overview():
    return jsonify(overview())


@bp.route("/api/bank/simulate", methods=["POST"])
def bank_simulate():
    body = request.get_json(silent=True) or {}
    n = body.get("n", 6)
    if not isinstance(n, int) or not 1 <= n <= 50:
        return jsonify({"error": "n must be 1-50"}), 422
    return jsonify(simulate(n))


@bp.route("/api/bank/scenario/compromised-device", methods=["POST"])
def scenario_compromised_device():
    """Demo: a sideloaded app is found on a customer's phone, then money leaves the account.
    Shows BlueWatch flagging the app, the bank flagging the payment, and a correlated incident."""
    import mobile_risk
    from soc import incidents

    body = request.get_json(silent=True) or {}
    victim_name = body.get("victim", "George Clark")
    model = mobile_risk.get_model()
    result = model.assess(SIDELOADED_FEATURES)
    note = f"sideloaded app scored {result['risk_score']} ({'flagged' if result['verdict'] == 'flag_for_review' else 'not flagged'})"
    assessment_id = store.record_assessment({**result, "sample_id": "sideloaded-demo-app"},
                                            SIDELOADED_FEATURES, f"scenario:{session['username']}", "scenario")
    victim = mark_device_risk(victim_name, result["risk_score"], note,
                              assessment_id=assessment_id)
    if victim is None:
        return jsonify({"error": f"no demo account matching '{victim_name}'"}), 404
    moved = compromised_device_transfer(victim)
    if moved is None:
        return jsonify({"error": "could not record the transfer"}), 500

    ctx = moved["cve"]
    summary = (f"A sideloaded Android app on {victim['name']}'s phone was flagged by BlueWatch "
               f"(risk score {result['risk_score']}). Minutes later, R{moved['tx']['amount']:,.0f} was "
               f"transferred from their account to “{moved['mule']['name']}”, a new payee. "
               + (f"The phone runs Android {ctx['version']} with {ctx['critical']} known critical "
                  f"vulnerabilities (NVD). " if ctx and ctx['critical'] else "")
               + "Freeze the payment for review and contact the customer. The score is decision "
                 "support — do not block the account automatically.")
    iid = incidents.create_manual(
        f"Possible account takeover: {victim['name']}", summary, "high", session["username"],
        tags=["mobile-malware", "account-takeover", "fraud"], assessment_id=assessment_id,
        entity=victim["name"])
    _log("BANK_FRAUD_FLAG", f"Incident {iid} opened for {victim['name']} (scenario: compromised-device)")
    return jsonify({"incident_id": iid, "app_risk": result, "transfer": moved["tx"],
                    "cve": ctx, "victim": victim["name"], "summary": summary}), 201
