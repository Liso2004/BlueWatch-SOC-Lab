# BlueWatch demo run, 2026-10-24 05:05

Lab only. Synthetic customers, payments and app data. The triage agent is a scripted playbook; people approve and close.

## 1. Lab activity

- SecureBank: 29 ordinary payments generated, 0 flagged by the bank's checks.
- 6 failed sign-ins on the `admin` account in under a minute.
- `jdoe` ran 3 wildcard customer searches returning 6304 records in total.
- 3 partner-API calls with a key BlueWatch does not recognise.
- Sideloaded-app scenario on Hannah Lewis's phone: app score 0.7759 (flag_for_review), R38,500.00 payment flagged, incident #1.

Detection rules ran: 5 new incident(s), 0 updated.

## 2. Clearing duplicates

- No duplicates: every open incident is a separate case.

6 open incidents became 6 cases.

## 3. Triage, routing and hand-offs

### #3 Large amount of customer data viewed by “jdoe”  (high)
- Assigned to **Liso**: insider-threat specialist with 0 open incident(s).
- Tagged `escalate` (high severity).
- Evidence summary added from 3 log event(s).
- Task for **analyst**: Ask the employee's manager whether this volume of customer lookups had a business reason.
- Review requested from **admin**.

### #1 Possible account takeover: Hannah Lewis  (high)
- Assigned to **Stacey-Lee**: mobile-malware specialist with 0 open incident(s).
- Tagged `escalate` (high severity).
- Case brief added, source: ai (qwen2.5:1.5b).
- Task for **Liso**: Call the customer on the number we hold (not one from the app), confirm the payment and walk them through removing the flagged app.
- Task for **analyst**: Hold the outgoing payment and check the new payee against mule lists.
- Review requested from **jdoe**.

### #6 Repeated rejected API keys  (medium)
- Assigned to **analyst**: api-abuse specialist with 0 open incident(s).
- Evidence summary added from 3 log event(s).
- Task for **jdoe**: Confirm which partner owns the rejected key and rotate it.
- Review requested from **admin** (BlueWatch suggested Stacey-Lee, who has no lab login).

### #5 Risky Android app found: sideloaded-demo-app  (medium)
- Assigned to **Stacey-Lee**: mobile-malware specialist with 1 open incident(s).
- Case brief added, source: template; fallback reason: AI summary failed the grounding check.
- Task for **Liso**: Find which customer phones reported this app and send them the in-app removal warning.
- Review requested from **jdoe**.

### #4 Very broad customer search by “jdoe”  (medium)
- Assigned to **Liso**: insider-threat specialist with 1 open incident(s).
- Evidence summary added from 3 log event(s).
- Task for **analyst**: Ask the employee's manager whether this volume of customer lookups had a business reason.
- Review requested from **admin** (BlueWatch suggested Stacey-Lee, who has no lab login).

### #2 Repeated failed sign-ins on account “admin”  (medium)
- Assigned to **analyst**: credential-attack specialist with 1 open incident(s); admin skipped because the incident is about them.
- Evidence summary added from 6 log event(s).
- Task for **jdoe**: Check where the failed sign-ins came from and force a password reset if needed.
- Review requested from **Stacey-Lee**.

## 4. The team signs in and finishes the work

- #3: 1 task(s) done, approved by admin, closed as resolved by analyst.
- #1: left open, the customer call is still outstanding (review waiting on jdoe).
- #6: admin sent it back asking for evidence; the analyst added it and asked again.
- #6: 1 task(s) done, approved by admin, closed as false alarm by analyst.
- #5: 1 task(s) done, approved by jdoe, closed as resolved by analyst.
- #4: 1 task(s) done, approved by admin, closed as resolved by analyst.
- #2: waiting for Stacey-Lee to sign off; nothing is closed without a review.

## 5. Where things stand

- Incidents by status: Investigating 2, Resolved 3, False alarm 1
- Open work per person: analyst 1/0/1, jdoe 0/1/1, admin 0/0/0, Liso 0/0/1, Stacey-Lee 1/1/0 (incidents / reviews / tasks)
- Run time: 138 s

## How to read this run

- **Re-run it:** `python insider-threat-lab/demo/team_triage_demo.py --log bluewatch-mobile/evidence/DEMO_RUN.md`
  with the lab running. It has no buttons; activity comes from `attacks/bank_activity.py`,
  `attacks/sideloaded_app_scenario.py` and this script.
- **What the "agent" is:** a fixed playbook (routing table, conflict-of-interest rule, review rule) on top of the
  detection rules, the ML risk score and the grounded case brief. It does not learn or act on its own judgement.
- **Team rules shown:** nobody handles or reviews an incident about themselves (enforced by the server, not just
  the playbook); nothing is closed without a reviewer's approval; a reviewer can send work back.
- **AI briefs:** written by a local model (Ollama, qwen2.5:1.5b) and checked against the facts before use. Briefs
  that fail the check (for example, calling an app "likely malicious", since the score is not a probability)
  are replaced by the template brief, and the log says so.
- **Lab limits:** Liso and Stacey-Lee have no lab logins, so reviews assigned to them stay waiting and their
  tasks are ticked off by the analyst on duty. Times in the app are UTC.
- **Known gap:** the account-takeover incident and the risky-app incident for the same sideloaded app are
  separate cases; they are not linked automatically yet.

Screenshots from this run: `screenshots/demo_*.png`.
