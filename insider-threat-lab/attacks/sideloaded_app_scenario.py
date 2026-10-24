#!/usr/bin/env python3
"""
Lab demo driver: "shady sideloaded app -> account takeover", end to end.

This is a SOC-lab simulation. It does NOT run any malware. It is an HTTP client that drives the
BlueWatch demo so the detection pipeline can be shown:

  1. makes SecureBank feel live by generating normal payments between accounts;
  2. submits the behavioural FEATURE COUNTS of a sideloaded banking-trojan-style app (overlay,
     accessibility, SMS, device-admin, persistence) to BlueWatch, which scores and flags it;
  3. simulates money leaving the victim's account to a new payee right after;
  4. lets the bank's fraud engine flag that payment, citing the flagged app and Android CVE
     context from NVD, and opens a correlated incident in the Security Center.

All data is synthetic. Run against the local lab only.

    python attacks/sideloaded_app_scenario.py              # full scenario
    python attacks/sideloaded_app_scenario.py --busy 20    # 20 normal payments first
"""

import argparse
import sys

import requests

BASE_URL = "http://127.0.0.1:5000"  # not "localhost": on Windows that can resolve to the WSL IPv6 relay


def login(session, username="analyst", password="password123"):
    r = session.post(f"{BASE_URL}/login", data={"username": username, "password": password},
                     allow_redirects=False)
    if r.status_code not in (302, 303):
        sys.exit(f"Login failed for {username} ({r.status_code}). Is the lab running on {BASE_URL}?")
    print(f"[+] Signed in as {username}")


def normal_activity(session, n):
    r = session.post(f"{BASE_URL}/api/bank/simulate", json={"n": n})
    r.raise_for_status()
    d = r.json()
    print(f"[+] Generated {d['created']} normal payment(s)" + (f", {d['flagged']} flagged" if d["flagged"] else ""))


def run_scenario(session, victim):
    r = session.post(f"{BASE_URL}/api/bank/scenario/compromised-device", json={"victim": victim})
    if r.status_code != 201:
        sys.exit(f"Scenario failed ({r.status_code}): {r.text}")
    d = r.json()
    app = d["app_risk"]
    print("\n=== Sideloaded-app -> account-takeover scenario ===")
    print(f"[app]    BlueWatch score {app['risk_score']} -> {app['verdict']}")
    present = [c["category"] for c in app["behaviour_profile"] if c["status"] == "present"]
    print(f"         banking-malware behaviours present: {', '.join(present) or 'none'}")
    tx = d["transfer"]
    print(f"[bank]   flagged payment: R{tx['amount']:,.2f}  {tx['from_name']} -> {tx['to_name']}")
    print(f"         reason: {tx['reason']}")
    if d.get("cve"):
        print(f"[cve]    Android {d['cve']['version']}: {d['cve']['critical']} critical, "
              f"{d['cve']['high']} high (NVD)")
    print(f"[soc]    incident #{d['incident_id']} opened: {BASE_URL}/security/incidents#incident-{d['incident_id']}")
    print("\nOpen the Security Center to assign it, pick a reviewer and add tasks.")


def main():
    ap = argparse.ArgumentParser(description="BlueWatch sideloaded-app demo scenario (lab only).")
    ap.add_argument("--busy", type=int, default=8, help="normal payments to generate first (1-50)")
    ap.add_argument("--victim", default="George Clark", help="demo customer whose device is compromised")
    args = ap.parse_args()
    session = requests.Session()
    login(session)
    normal_activity(session, max(1, min(50, args.busy)))
    run_scenario(session, args.victim)


if __name__ == "__main__":
    main()
