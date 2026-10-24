#!/usr/bin/env python3
"""
End-to-end lab demo: BlueWatch's triage playbook working the Security Center with the team.

What the "triage agent" is, honestly: a scripted playbook. It reads the incidents the detection
rules open, uses the ML risk score and the grounded AI case brief already built into BlueWatch,
and applies fixed team rules (routing, conflict of interest, review). It never approves or closes
its own work: reviewers sign in as themselves to approve, and the analyst on duty resolves.

Run against the local lab only. All customers, payments and apps are synthetic.

    python demo/team_triage_demo.py                     # full run, log to stdout
    python demo/team_triage_demo.py --log run.md        # also write a Markdown run log
"""

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime

import requests

BASE_URL = "http://127.0.0.1:5000"  # not "localhost": on Windows that can resolve to the WSL IPv6 relay
LAB_PASSWORD = "password123"          # seeded lab accounts only (init_db.sql)
OLLAMA_URL = os.getenv("OLLAMA_HOST_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("AI_MODEL", "qwen2.5:1.5b")
CAN_SIGN_IN = ["analyst", "admin", "jdoe"]
ON_DUTY = "analyst"

# Who the playbook prefers for each kind of incident, before balancing load.
SPECIALISTS = {
    "mobile-malware": ["Stacey-Lee", "Liso"],
    "credential-attack": ["admin", "analyst"],
    "insider-threat": ["Liso", "analyst"],
    "api-abuse": ["analyst", "admin"],
}
FIRST_STEPS = {
    "mobile-malware": ("Liso", "Find which customer phones reported this app and send them the in-app removal warning."),
    "account-takeover": ("Stacey-Lee", "Hold the outgoing payment and check the new payee against mule lists."),
    "customer-call": ("Liso", "Call the customer on the number we hold (not one from the app), confirm the payment "
                              "and walk them through removing the flagged app."),
    "credential-attack": ("admin", "Check where the failed sign-ins came from and force a password reset if needed."),
    "insider-threat": ("Liso", "Ask the employee's manager whether this volume of customer lookups had a business reason."),
    "api-abuse": ("analyst", "Confirm which partner owns the rejected key and rotate it."),
}

log_lines = []


def say(text=""):
    print(text)
    log_lines.append(text)


def signed_in(user):
    s = requests.Session()
    r = s.post(f"{BASE_URL}/login", data={"username": user, "password": LAB_PASSWORD}, allow_redirects=False)
    if r.status_code not in (302, 303):
        sys.exit(f"Could not sign in as {user} ({r.status_code}). Is the lab running on {BASE_URL}?")
    return s


def call(s, method, path, **kw):
    r = s.request(method, f"{BASE_URL}{path}", timeout=kw.pop("timeout", 30), **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:200]}")
    return r.json()


# --- act 1: the bank is busy, then things go wrong ------------------------------------------

def generate_activity(analyst):
    say("## 1. Lab activity\n")
    made = flagged = 0
    for _ in range(3):
        d = call(analyst, "POST", "/api/bank/simulate", json={"n": 10})
        made += d["created"]
        flagged += d["flagged"]
    say(f"- SecureBank: {made} ordinary payments generated, {flagged} flagged by the bank's checks.")

    bad = requests.Session()
    for _ in range(6):
        bad.post(f"{BASE_URL}/login", data={"username": "admin", "password": "wrong-guess"}, allow_redirects=False)
    say("- 6 failed sign-ins on the `admin` account in under a minute.")

    jdoe = signed_in("jdoe")
    rows = sum(len(call(jdoe, "GET", "/api/search", params={"q": q})) for q in ("a", "e", "o"))
    say(f"- `jdoe` ran 3 wildcard customer searches returning {rows} records in total.")

    for _ in range(3):
        requests.get(f"{BASE_URL}/api/v1/mobile/model", headers={"X-API-Key": "not-a-real-key"})
    say("- 3 partner-API calls with a key BlueWatch does not recognise.")

    d = call(analyst, "POST", "/api/bank/scenario/compromised-device", json={"victim": "Hannah Lewis"}, timeout=180)
    say(f"- Sideloaded-app scenario on Hannah Lewis's phone: app score {d['app_risk']['risk_score']} "
        f"({d['app_risk']['verdict']}), R{d['transfer']['amount']:,.2f} payment flagged, incident #{d['incident_id']}.")
    say()


# --- act 2: the playbook triages the queue ------------------------------------------------------

def category(inc):
    for tag in ("mobile-malware", "credential-attack", "insider-threat", "api-abuse"):
        if tag in inc["tags"]:
            return tag
    return "api-abuse" if inc["rule"] == "api_abuse" else "insider-threat"


def pick_owner(inc, load):
    """Specialist first, then whoever has least open work - never the person the incident is about."""
    banned = {inc.get("entity")}
    pool = [p for p in SPECIALISTS[category(inc)] if p not in banned] or [p for p in load if p not in banned]
    owner = min(pool, key=lambda p: (load[p], pool.index(p)))
    why = f"{category(inc)} specialist with {load[owner]} open incident(s)"
    if inc.get("entity") in SPECIALISTS[category(inc)]:
        why += f"; {inc['entity']} skipped because the incident is about them"
    return owner, why


def dedupe(analyst, queue):
    say("## 2. Clearing duplicates\n")
    groups = defaultdict(list)
    for inc in queue:
        groups[(inc["rule"], inc.get("entity"))].append(inc)
    keep = []
    for (rule, entity), incs in groups.items():
        incs.sort(key=lambda i: i["id"], reverse=True)
        keep.append(incs[0])
        for dup in incs[1:]:
            call(analyst, "POST", f"/api/soc/incidents/{dup['id']}/notes",
                 json={"text": f"[triage playbook] Same {rule.replace('_', ' ')} pattern for {entity} as "
                               f"#{incs[0]['id']}; closing this copy so the team works one case."})
            call(analyst, "PATCH", f"/api/soc/incidents/{dup['id']}", json={"status": "resolved", "add_tag": "duplicate"})
        if len(incs) > 1:
            say(f"- Kept #{incs[0]['id']} ({rule}, {entity}); closed {', '.join('#' + str(d['id']) for d in incs[1:])} "
                f"as duplicates.")
    if len(keep) == len(queue):
        say("- No duplicates: every open incident is a separate case.")
    say(f"\n{len(queue)} open incidents became {len(keep)} cases.\n")
    return sorted(keep, key=lambda i: ({"high": 0, "medium": 1, "low": 2}[i["severity"]], -i["id"]))


def brief_for(analyst, inc):
    if not inc.get("assessment_id"):
        return None
    try:
        b = call(analyst, "POST", "/api/mobile/brief", json={"assessment_id": inc["assessment_id"]}, timeout=200)
    except RuntimeError as e:
        say(f"- Case brief unavailable ({e}).")
        return None
    return b


def triage(analyst, cases):
    say("## 3. Triage, routing and hand-offs\n")
    team = call(analyst, "GET", "/api/soc/team")
    load = {w["name"]: w["assigned"] for w in team["workload"]}
    plan = []
    for inc in cases:
        detail = call(analyst, "GET", f"/api/soc/incidents/{inc['id']}")
        if any(n["text"].startswith("[triage playbook] Case brief") or n["text"].startswith("[triage playbook] Rule")
               for n in detail.get("notes", [])) and detail["assignee"]:
            say(f"### #{inc['id']} {inc['title']}  ({inc['severity']})\n- Already triaged on an earlier run: "
                f"with {detail['assignee']}, reviewer {detail['reviewer'] or 'none'}.\n")
            plan.append((inc, detail["assignee"], detail["reviewer"]))
            continue
        cat = category(inc)
        owner, why = pick_owner(inc, load)
        load[owner] += 1
        say(f"### #{inc['id']} {inc['title']}  ({inc['severity']})")
        call(analyst, "PATCH", f"/api/soc/incidents/{inc['id']}", json={"assignee": owner, "status": "investigating"})
        say(f"- Assigned to **{owner}**: {why}.")
        if inc["severity"] == "high" and "escalate" not in inc["tags"]:
            call(analyst, "PATCH", f"/api/soc/incidents/{inc['id']}", json={"add_tag": "escalate"})
            say("- Tagged `escalate` (high severity).")

        b = brief_for(analyst, inc)
        if b:
            src = b["generated_by"] + (f" ({b['model']})" if b.get("model") else "")
            call(analyst, "POST", f"/api/soc/incidents/{inc['id']}/notes",
                 json={"text": f"[triage playbook] Case brief, written by {src} and checked against the score:\n"
                               f"{b['summary']}"[:2000]})
            say(f"- Case brief added, source: {src}" + (f"; fallback reason: {b['reason']}" if b.get("reason") else "") + ".")
        else:
            call(analyst, "POST", f"/api/soc/incidents/{inc['id']}/notes",
                 json={"text": f"[triage playbook] Rule `{inc['rule']}` matched {inc['event_count']} log event(s). "
                               f"{inc['summary']}"[:2000]})
            say(f"- Evidence summary added from {inc['event_count']} log event(s).")

        if "account-takeover" in inc["tags"]:
            steps = [FIRST_STEPS["customer-call"], FIRST_STEPS["account-takeover"]]
        else:
            steps = [FIRST_STEPS[cat]]
        for who, text in steps:
            if who in (owner, inc.get("entity")):
                who = next(p for p in load if p not in (owner, inc.get("entity")))
            call(analyst, "POST", f"/api/soc/incidents/{inc['id']}/tasks", json={"assignee": who, "text": text})
            say(f"- Task for **{who}**: {text}")

        sug = call(analyst, "GET", f"/api/soc/incidents/{inc['id']}/suggest-reviewer")
        names = [c["name"] for c in sug["candidates"]]
        eligible = [n for n in names if n != inc.get("entity")]
        # Prefer someone who can sign in to the lab, so the demo can show the approval; otherwise
        # the suggested person still gets the review and the incident waits for them.
        reviewer = next((n for n in eligible if n in CAN_SIGN_IN), eligible[0] if eligible else None)
        if reviewer:
            call(analyst, "POST", f"/api/soc/incidents/{inc['id']}/review",
                 json={"reviewer": reviewer, "action": "request"})
            note = "" if reviewer == sug["suggested"] else f" (BlueWatch suggested {sug['suggested']}, who has no lab login)"
            say(f"- Review requested from **{reviewer}**{note}.")
        else:
            say("- No reviewer without a conflict of interest is free; left for the team lead to pick.")
        plan.append((inc, owner, reviewer))
        say()
    return plan


# --- act 3: people do their part ------------------------------------------------------------

def team_work(analyst, plan, keep_open):
    say("## 4. The team signs in and finishes the work\n")
    sessions = {u: signed_in(u) for u in CAN_SIGN_IN}
    sessions[ON_DUTY] = analyst
    sent_back = False
    for inc, owner, reviewer in plan:
        iid = inc["id"]
        if reviewer and not sent_back and inc["severity"] == "medium":
            call(sessions[reviewer], "POST", f"/api/soc/incidents/{iid}/review", json={"action": "send_back"})
            call(sessions[reviewer], "POST", f"/api/soc/incidents/{iid}/notes",
                 json={"text": "Please attach the list of customers viewed before I sign this off."})
            call(analyst, "POST", f"/api/soc/incidents/{iid}/notes",
                 json={"text": "Customer list from the search logs attached to the evidence tab."})
            call(analyst, "POST", f"/api/soc/incidents/{iid}/review", json={"action": "request"})
            say(f"- #{iid}: {reviewer} sent it back asking for evidence; the analyst added it and asked again.")
            sent_back = True
        if iid in keep_open:
            say(f"- #{iid}: left open, the customer call is still outstanding (review waiting on {reviewer}).")
            continue
        if reviewer not in CAN_SIGN_IN:
            say(f"- #{iid}: waiting for {reviewer or 'a reviewer'} to sign off; nothing is closed without a review.")
            continue
        detail = call(analyst, "GET", f"/api/soc/incidents/{iid}")
        for t in detail["tasks"]:
            if not t["done"]:
                call(analyst, "PATCH", f"/api/soc/incidents/{iid}/tasks/{t['id']}", json={"done": True})
        if reviewer:
            call(sessions[reviewer], "POST", f"/api/soc/incidents/{iid}/review", json={"action": "approve"})
        outcome = "false_positive" if inc["rule"] == "api_abuse" else "resolved"
        call(analyst, "PATCH", f"/api/soc/incidents/{iid}", json={"status": outcome})
        say(f"- #{iid}: {len(detail['tasks'])} task(s) done, approved by {reviewer or 'nobody'}, "
            f"closed as {'false alarm' if outcome == 'false_positive' else 'resolved'} by {ON_DUTY}.")
    say()


def main():
    ap = argparse.ArgumentParser(description="BlueWatch end-to-end team triage demo (lab only).")
    ap.add_argument("--log", help="write the run log as Markdown to this path")
    args = ap.parse_args()

    started = time.time()
    say(f"# BlueWatch demo run, {datetime.now():%Y-%m-%d %H:%M}\n")
    say("Lab only. Synthetic customers, payments and app data. The triage agent is a scripted playbook; "
        "people approve and close.\n")
    analyst = signed_in(ON_DUTY)
    call(analyst, "GET", "/api/mobile/model", timeout=300)  # first call after a restart loads the classifier
    try:  # load the local model into memory now, so the first case brief is not a cold start
        requests.post(f"{OLLAMA_URL}/api/generate", json={"model": OLLAMA_MODEL, "keep_alive": "30m"}, timeout=120)
    except requests.RequestException:
        pass  # BlueWatch falls back to its template brief if the model is unavailable

    generate_activity(analyst)
    sync = call(analyst, "POST", "/api/soc/sync")
    say(f"Detection rules ran: {sync['new']} new incident(s), {sync['updated']} updated.\n")

    queue = [i for i in call(analyst, "GET", "/api/soc/incidents") if i["status"] in ("new", "investigating")]
    cases = dedupe(analyst, queue)
    plan = triage(analyst, cases)
    takeover = [inc["id"] for inc, _, _ in plan if "account-takeover" in inc["tags"]]
    team_work(analyst, plan, keep_open=set(takeover[:1]))

    counts = defaultdict(int)
    for i in call(analyst, "GET", "/api/soc/incidents"):
        counts[i["status_label"]] += 1
    say("## 5. Where things stand\n")
    say("- Incidents by status: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    wl = call(analyst, "GET", "/api/soc/team")["workload"]
    say("- Open work per person: " + ", ".join(f"{w['name']} {w['assigned']}/{w['reviews']}/{w['tasks']}" for w in wl)
        + " (incidents / reviews / tasks)")
    say(f"- Run time: {time.time() - started:.0f} s")

    if args.log:
        with open(args.log, "w", encoding="utf-8") as f:
            f.write(re.sub(r"\n{3,}", "\n\n", "\n".join(log_lines)) + "\n")
        print(f"\n[+] Log written to {args.log}")


if __name__ == "__main__":
    main()
