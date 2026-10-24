#!/usr/bin/env python3
"""
Lab traffic generator: keeps the simulated SecureBank ledger busy so the home page feels live.

Each round asks the lab to create a few ordinary payments between the seeded demo accounts. The
bank's own checks decide which ones get flagged (large amounts, devices already marked risky).
All data is synthetic. Run against the local lab only.

    python attacks/bank_activity.py                       # 12 rounds, one every 5 seconds
    python attacks/bank_activity.py --rounds 0            # run until Ctrl+C
    python attacks/bank_activity.py --per-round 10 --interval 2
"""

import argparse
import sys
import time

import requests

BASE_URL = "http://127.0.0.1:5000"  # not "localhost": on Windows that can resolve to the WSL IPv6 relay


def login(session, username="analyst", password="password123"):
    r = session.post(f"{BASE_URL}/login", data={"username": username, "password": password},
                     allow_redirects=False)
    if r.status_code not in (302, 303):
        sys.exit(f"Login failed for {username} ({r.status_code}). Is the lab running on {BASE_URL}?")
    print(f"[+] Signed in as {username}")


def main():
    ap = argparse.ArgumentParser(description="Generate simulated SecureBank payments (lab only).")
    ap.add_argument("--rounds", type=int, default=12, help="rounds to run; 0 = until Ctrl+C")
    ap.add_argument("--per-round", type=int, default=4, help="payments per round (1-50)")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between rounds")
    args = ap.parse_args()

    session = requests.Session()
    login(session)
    n = max(1, min(50, args.per_round))
    done = created = flagged = 0
    try:
        while args.rounds == 0 or done < args.rounds:
            r = session.post(f"{BASE_URL}/api/bank/simulate", json={"n": n})
            r.raise_for_status()
            d = r.json()
            done += 1
            created += d["created"]
            flagged += d["flagged"]
            print(f"[{done:>3}] {d['created']} payment(s)" + (f", {d['flagged']} flagged" if d["flagged"] else ""))
            if args.rounds == 0 or done < args.rounds:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    print(f"[+] {created} payments in {done} round(s), {flagged} flagged by the bank's checks")


if __name__ == "__main__":
    main()
