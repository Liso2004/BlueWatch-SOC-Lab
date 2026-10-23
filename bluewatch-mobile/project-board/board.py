#!/usr/bin/env python3
"""
BlueWatch Mobile project board: single source of truth for issues, labels,
milestones and Projects v2 fields.

    python board.py export            # write issues.csv + ISSUES.md (no network)
    python board.py apply --dry-run   # print every gh call without running it
    python board.py apply             # create labels, milestones, issues; sync project 3

`apply` needs the GitHub CLI authenticated with the `project` scope:
    gh auth login && gh auth refresh -s project
It targets the existing project https://github.com/users/Liso2004/projects/3 and is
idempotent: existing issues (by title) are reused, and every item's fields are re-set.
"""

import csv
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = "Liso2004/BlueWatch-SOC-Lab"
OWNER = "Liso2004"
PROJECT_TITLE = "BlueWatch Mobile — YES AI Hackathon & Product Roadmap"
PROJECT_NUMBER = "3"
GH = r"C:\Program Files\GitHub CLI\gh.exe"
HERE = Path(__file__).parent

STATUS = ["Backlog", "Ready", "In Progress", "Blocked", "Review / Testing", "Done"]
PRIORITY = {"P0": "P0 Critical", "P1": "P1 High", "P2": "P2 Later"}
PHASES = ["Hackathon", "0–30 days", "30–90 days", "3–6 months", "6–12 months"]
WORKSTREAMS = ["Product", "Data", "ML", "Backend/API", "Frontend", "Security/Privacy",
               "Threat Intelligence", "Testing", "Pitch", "Commercial", "Documentation"]

MILESTONES = [
    ("Hackathon: video submission", "2026-10-24T05:00:00Z",
     "3-minute team video due Sat 24 Oct 2026 07:00 SAST (05:00 UTC)."),
    ("Hackathon: live pitch & judging", None,
     "5-min pitch, max 3 slides, 2-min Q&A. Exact slot to confirm from agenda."),
    ("Post-event: 0–30 days", "2026-11-23T22:00:00Z", "Reproducibility, data/model cards, discovery start."),
    ("Post-event: 30–90 days", "2027-01-22T22:00:00Z", "Validation, collector feasibility, release governance."),
    ("Post-event: 3–6 months", "2027-04-23T22:00:00Z", "Design-partner pilot."),
    ("Post-event: 6–12 months", "2027-10-23T22:00:00Z", "Pricing, enterprise hardening, scale metrics."),
]
PHASE_MILESTONE = {
    "Hackathon": "Hackathon: video submission",
    "0–30 days": "Post-event: 0–30 days",
    "30–90 days": "Post-event: 30–90 days",
    "3–6 months": "Post-event: 3–6 months",
    "6–12 months": "Post-event: 6–12 months",
}

LABELS = {
    "p0": "b60205", "p1": "d93f0b", "p2": "fbca04",
    "bluewatch-mobile": "0e8a16", "security": "b60205",
    "needs-confirmation": "c5def5",
    **{"ws:" + w.lower().replace("/", "-").replace(" ", "-"): "1d76db" for w in WORKSTREAMS},
}

ROLES = {
    "TL": "Tech Lead (Liso Wycliff Seth Hlatshwayo)",
    "FS": "Full Stack / Prototype Engineer (Stacey-Lee Pietersen)",
    "DEVSEC": "Cloud & DevSecOps Engineer (YES-sponsored role — onboarding unconfirmed)",
    "DATA": "Data & MLOps Engineer (YES-sponsored role — onboarding unconfirmed)",
    "BIZ": "Founder / Business Lead (Liso Wycliff Seth Hlatshwayo)",
    "TEAM": "Whole team",
}

ORG = "Organiser requirement as relayed in the team master prompt §4; organiser documents not yet reviewed directly in this repo — confirm against the Participant Pack."

# Repo facts this board relies on (verified 2026-10-23 against origin/bulk @ fbaf76d):
#  - no Android, ML, FastAPI or React code exists yet; repo is the SOC Lab (Flask/MySQL/ELK/Wazuh)
#  - origin/main contains only the initial commit; real work is on `bulk`
#  - repo is public; a private key and DB credentials are committed in history
ISSUES = [
    dict(id="SEC", pri="P0", phase="Hackathon", ws=["Security/Privacy"], owner="TL", private=True,
         title="[P0] Rotate exposed credentials and remove tracked private key",
         problem="The public repository tracks a Wazuh manager private key (since b23edd4, 2026-01-19) and has hard-coded MySQL/root passwords in committed code, compose files and docs. Values are not reproduced here.",
         impl="1. Treat all committed DB/root passwords and the Wazuh key/cert as compromised; rotate/regenerate. 2. Stop tracking the key (`git rm --cached`) and rely on .gitignore (*.key already added). 3. Remove remaining hard-coded values from reset_passwords.py and docs/setup_guide.md. 4. Decide with the owner whether to rewrite history (BFG/git-filter-repo) — needs explicit approval and force-push coordination. 5. Enable GitHub secret scanning / push protection.",
         deps="None — do first.",
         ac=["All previously committed secrets rotated and old values no longer valid", "No private keys or real passwords in the current tree (`git grep` clean)", ".env.example contains placeholders only", "History-rewrite decision recorded"],
         source="Master prompt §6 security check; repository inspection.",
         safety="Track privately (GitHub security advisory or private channel), not a public issue with details. Never paste secret values into issues, PRs or chat."),

    dict(id=1, pri="P0", phase="Hackathon", ws=["Product"], owner="TL",
         title="[P0] Freeze MVP scope and define minimum end-to-end demo",
         problem="No Challenge 3 code exists in the repo yet (verified 2026-10-23). The existing SOC Lab is insider-threat/ELK/Wazuh work and is not Android malware detection. With the video due 24 Oct 07:00 SAST, scope must be one thin, honest slice.",
         impl="Scope: labelled behavioural feature rows from one permitted dataset -> deterministic preprocessing -> one baseline classifier -> FastAPI /predict -> single dashboard page showing verdict, score, top contributing features, model version. Put new code under `bluewatch-mobile/` to keep it separate from SOC Lab prior work. Work on a feature branch; PR into `bulk` (or a new default) only after review.",
         deps="SEC issue in parallel.",
         ac=["One-paragraph scope committed to bluewatch-mobile/README.md", "Owners by role recorded", "Branch/PR rule and definition of done agreed", "Explicit out-of-scope list (Android collector, live threat feeds, cloud deploy)"],
         source=ORG, safety="Do not present SOC Lab results as BlueWatch Mobile results."),

    dict(id=2, pri="P0", phase="Hackathon", ws=["Data"], owner="DATA",
         title="[P0] Confirm dataset, licence/terms, label provenance and split",
         problem="Model claims are only defensible if the dataset source, version, terms and labels are known. Candidate sources from the proposal: CICMalDroid 2020 (https://www.unb.ca/cic/datasets/maldroid-2020.html), KronoDroid (https://www.sciencedirect.com/science/article/pii/S0167404821002236). Terms not yet verified.",
         impl="Pick one source that ships pre-extracted behavioural/static features (no raw malware binaries needed). Record URL, retrieval date, file hash, terms/citation requirement, label scheme (binary vs family/category) and class counts in `bluewatch-mobile/data/DATA_REGISTER.md`. Keep raw data out of git unless terms allow redistribution.",
         deps="#1",
         ac=["DATA_REGISTER.md with source URL, version/date, SHA-256, terms link/quote, citation, label provenance, class counts", "Decision on split strategy recorded", "Data files gitignored unless redistribution is permitted"],
         source=ORG + " README must disclose datasets.",
         safety="No malware binaries on event laptops; no personal data. Check commercial-use terms before any pilot."),

    dict(id=3, pri="P0", phase="Hackathon", ws=["Data", "Backend/API", "Frontend"], owner="TL",
         title="[P0] Define versioned feature schema and label mapping",
         problem="Data, API and UI must agree on feature names, types and labels or the demo breaks at integration.",
         impl="`bluewatch-mobile/schema/features_v1.json` (name, type, range, description, missing-value rule) plus label map. Generate the Pydantic request model from it. Include 1 benign + 1 malicious sample request.",
         deps="#2",
         ac=["Schema file with version string", "Data dictionary readable by non-ML teammates", "Sample requests validate against API model"],
         source="Board import (BlueWatch_Mobile_Project_Board.csv).",
         safety="Exclude any field that could hold credentials, OTPs or message content."),

    dict(id=4, pri="P0", phase="Hackathon", ws=["Data", "ML"], owner="DATA",
         title="[P0] Reproducible preprocessing with leakage and imbalance checks",
         problem="Hidden duplicates or leakage between train and test inflate metrics and are a common judge/investor challenge.",
         impl="`python -m bluewatch_mobile.prepare` reads the raw file, applies schema, handles missing values, de-duplicates, writes a parquet/CSV feature matrix and a JSON report (rows, duplicates dropped, class balance, train/test overlap).",
         deps="#2, #3",
         ac=["One command recreates the matrix from raw data", "Fixed random seed", "Report records duplicates, missing values, class counts, train/test overlap = 0"],
         source="Master prompt §7.6.", safety="—"),

    dict(id=5, pri="P0", phase="Hackathon", ws=["ML"], owner="DATA",
         title="[P0] Train baseline classifier and record metrics on held-out split",
         problem="We need one real, measured model rather than claimed accuracy.",
         impl="Start with scikit-learn RandomForest (fast, explainable via feature importances). Try XGBoost only if time allows. Save model + metadata (version, data hash, features version, seed). Write metrics.json: precision, recall, F1, FPR, confusion matrix, PR-AUC, test size and class balance.",
         deps="#4",
         ac=["Model artefact with version metadata", "metrics.json from held-out split only", "Split method documented (random vs time/family-aware)", "No metric quoted anywhere that is not in metrics.json"],
         source="Master prompt §7.5.", safety="Score is not a calibrated probability unless calibration is tested — label it 'risk score'."),

    dict(id=6, pri="P0", phase="Hackathon", ws=["Backend/API", "Testing"], owner="DEVSEC",
         title="[P0] Inference API contract with validation and tests",
         problem="The dashboard and demo need a real inference endpoint with defined semantics.",
         impl="Built as a Flask blueprint inside the SOC Lab banking app (team decision 2026-10-23): insider-threat-lab/app/mobile_risk/. Login-protected. GET /api/mobile/model, GET /api/mobile/samples, POST /api/mobile/assess -> {verdict, risk_score, score_semantics, evidence[], banking_indicators_present[], model_version, features_version, disclaimer}; 400/404/422 with readable errors; every assessment logged as MOBILE_RISK_ASSESSMENT for ELK/Wazuh. Tests: insider-threat-lab/app/tests/test_mobile_risk.py. A standalone FastAPI service remains an option post-event.",
         deps="#3, #5",
         ac=["pytest passes for valid, invalid and missing-field requests", "Response comes from the loaded model (no hard-coded verdicts)", "Model/version fields populated", "Runs with one documented command"],
         source="Board import.", safety="Bind to localhost for the demo; add API key before any non-local exposure."),

    dict(id=7, pri="P0", phase="Hackathon", ws=["Frontend"], owner="FS",
         title="[P0] Connect analyst dashboard to real API results",
         problem="Judges must see the working solution; a UI showing mocked verdicts would be misleading.",
         impl="Built as a server-rendered page in the banking app (templates/mobile_risk.html, /mobile-risk): pick a labelled sample, call /api/mobile/assess, show verdict, risk score vs threshold, evidence table, banking-related capabilities, model version, evaluation table with drift warning and a human-review banner. Remaining: click-through in a browser against the Docker stack. React/TypeScript dashboard is post-event.",
         deps="#6",
         ac=["At least one sample round-trips UI -> API -> UI", "Error shown on API failure", "No hard-coded verdicts in UI code", "Expected label shown next to prediction for demo samples"],
         source=ORG + " Video must show the working solution.", safety="—"),

    dict(id=8, pri="P0", phase="Hackathon", ws=["Testing"], owner="TEAM",
         title="[P0] Run 3 malicious + 3 benign labelled samples end to end",
         problem="The demo needs recorded evidence, including failures.",
         impl="Pick 6 held-out test rows (not used in training). Run each through the UI path. Record in `bluewatch-mobile/evidence/demo_cases.md`: sample id, source, expected label, predicted verdict, score, pass/fail, screenshot.",
         deps="#7",
         ac=["Six cases recorded with actual outputs", "Any misclassification kept and explained, not hidden", "States that six cases demonstrate workflow, not efficacy"],
         source="Master prompt §7.6.", safety="—"),

    dict(id=9, pri="P0", phase="Hackathon", ws=["Pitch"], owner="FS",
         title="[P0] Record 3-minute video and upload/verify before Sat 07:00 SAST",
         problem="Hard deadline: one team video, max 3:00, due Saturday 24 Oct 2026 07:00 SAST; must show the working solution.",
         impl="Script to organiser timing: 0:00–0:30 problem; 0:30–1:45 live demo; 1:45–2:30 value + AI; 2:30–3:00 responsible AI + next steps. Screen-record actual UI. Upload early (target before midnight) and screenshot the platform confirmation.",
         deps="#8",
         ac=["Duration <= 3:00", "Real outputs shown; planned features labelled 'planned'", "Accepted format/size checked on platform", "Upload confirmation screenshot saved"],
         source=ORG, safety="No credentials, personal data or real customer info on screen."),

    dict(id=10, pri="P0", phase="Hackathon", ws=["Documentation"], owner="TL",
         title="[P0] Complete AI/data/API/third-party/pre-existing-work README disclosure",
         problem="The participant pack requires disclosure of AI tools, models, APIs, datasets, third-party material, pre-existing work and team contribution.",
         impl="Fill BlueWatch_Mobile_README_Disclosure_Template into bluewatch-mobile/README.md from actual code, requirements and git log. Pre-existing: SOC Lab (Jan 2026 commits). Event work: everything under bluewatch-mobile/. AI tools: list each actually used (incl. Claude Code for repo audit/board generation).",
         deps="#5, #6, #7",
         ac=["No TODOs", "Every dependency in requirements/package.json listed with licence", "Pre-existing vs event work separated with commit refs", "All AI tools used are disclosed"],
         source=ORG, safety="No POPIA-compliance claims."),

    dict(id=11, pri="P0", phase="Hackathon", ws=["Pitch"], owner="TL", milestone="Hackathon: live pitch & judging",
         title="[P0] Prepare 3-slide / 5-minute live pitch and 2-minute Q&A bank",
         problem="Master Operational Document specifies 5-min pitch, max 3 slides, 2-min Q&A; Pitch Instructions noted some details pending — prepare for the stricter format.",
         impl="Slide 1 problem + who benefits; slide 2 architecture + live demo (fallback video); slide 3 roadmap + business (pricing labelled as assumption). Q&A bank: dataset, metrics, false positives, privacy, collector feasibility, competition, pricing.",
         deps="#8",
         ac=["Rehearsed under 5:00", "<= 3 slides", "Fallback demo ready offline", "Q&A owners assigned", "Format confirmed with organisers"],
         source=ORG, safety="Market figures (TAM R151.2m etc.) labelled as unverified planning assumptions."),

    dict(id=12, pri="P0", phase="Hackathon", ws=["Security/Privacy"], owner="DEVSEC",
         title="[P0] Security and privacy preflight before demo",
         problem="Public repo + demo recording; need to confirm nothing sensitive ships.",
         impl="Run gitleaks/`git grep` on the branch; confirm .env untracked; check demo samples contain no personal data; check logs; confirm UI disclaimer about human review; confirm API not exposed publicly.",
         deps="SEC, #7",
         ac=["Secret scan clean on submission branch", "Demo data reviewed", "Human-in-the-loop statement visible in UI and README"],
         source="Master prompt §7.", safety="—"),

    dict(id=13, pri="P0", phase="Hackathon", ws=["Testing", "Documentation"], owner="DATA",
         title="[P0] Capture reproducibility evidence pack",
         problem="Claims need a commit hash, data hash and model version behind them.",
         impl="`bluewatch-mobile/evidence/EVIDENCE.md`: commit SHA, dataset hash/version, features version, model version, split, metrics.json, demo_cases.md, screenshots, known limitations; each item tagged Implemented / Tested / Mocked / Planned.",
         deps="#5, #8",
         ac=["Every number in video/pitch traceable to this file", "Limitations section present", "Status tags on every component"],
         source="Master prompt §10.", safety="—"),

    dict(id=14, pri="P1", phase="0–30 days", ws=["Testing", "Documentation"], owner="TL",
         title="[P1] Reproduce baseline from a clean clone",
         problem="A result only one laptop can produce is not evidence.",
         impl="Fresh clone + fresh venv/container; follow README only; record any gaps. Add CI job that runs preprocessing on a fixture and the API tests.",
         deps="#13", ac=["Second person reproduces metrics.json within tolerance", "CI green", "README setup steps tested"],
         source="Board import.", safety="—"),

    dict(id=15, pri="P1", phase="0–30 days", ws=["Data", "ML", "Documentation"], owner="DATA",
         title="[P1] Data card and model card",
         problem="Buyers and reviewers need documented intended use, limits and provenance.",
         impl="DATA_CARD.md (source, terms, collection period, Android versions, label method, known biases) and MODEL_CARD.md (intended use, out-of-scope use, metrics by class, thresholds, limitations).",
         deps="#2, #5", ac=["Both cards committed and linked from README", "Out-of-scope uses explicit"],
         source="NIST AI RMF (https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf).", safety="—"),

    dict(id=16, pri="P1", phase="30–90 days", ws=["ML", "Testing"], owner="DATA",
         title="[P1] Time/family/source-aware evaluation and false-positive burden",
         problem="Random splits overstate performance on new malware families and newer Android versions.",
         impl="Where metadata allows, evaluate train-on-older/test-on-newer and leave-family-out. Estimate analyst workload (alerts/day) at chosen thresholds.",
         deps="#14", ac=["Report comparing random vs temporal/family splits", "Threshold rationale documented", "FPR translated to analyst workload"],
         source="Master prompt §7.6.", safety="—"),

    dict(id=17, pri="P1", phase="30–90 days", ws=["Product", "Security/Privacy"], owner="TL",
         title="[P1] Non-root Android telemetry feasibility review",
         problem="Research-dataset features may not be observable by a non-root app on modern Android; the product depends on this gap being closable.",
         impl="Map each model feature to an obtainable signal on Android without root, with required permission, OS versions and Play policy constraints. Sources: https://developer.android.com/guide/topics/permissions/overview, https://developer.android.com/guide/topics/ui/accessibility/service, https://mas.owasp.org/MASVS/.",
         deps="#3", ac=["Feature-to-signal matrix with 'obtainable / partial / not obtainable'", "Policy risks listed", "Go/no-go recommendation for collector build"],
         source="Master prompt §6.", safety="Data minimisation: no message bodies, OTPs or screen content."),

    dict(id=18, pri="P1", phase="30–90 days", ws=["Threat Intelligence", "ML", "Security/Privacy"], owner="DEVSEC",
         title="[P1] Threat-intel staging and model release governance",
         problem="Live feeds must not silently change model behaviour.",
         impl="Implemented at hackathon: NVD CVE API 2.0 Android platform context (mobile_risk/nvd.py) with CPE-based matching, 24h cache, retrieval timestamps, separate UI panel. Remaining (Planned): incremental sync via lastModStartDate instead of full refetch; app/component version matching once collector supplies versions; MISP or other malware-intel feeds with provenance and licence review; model registry with staging -> evaluation -> approval -> release and tested rollback. TI never changes the ML verdict automatically.",
         deps="#15", ac=["Documented release checklist", "Tested rollback to previous model", "TI source register with terms"],
         source="Master prompt §6–7.", safety="A CVE alone does not prove an app is malicious."),

    dict(id=19, pri="P1", phase="0–30 days", ws=["Commercial"], owner="BIZ",
         title="[P1] 10–15 discovery interviews with target practitioners",
         problem="Buyer, pain and willingness to pay are unvalidated.",
         impl="Interview bank/fintech SOC, fraud, mobile-security and MSSP practitioners. Fixed script: current workflow, tools, unmet need, buyer, budget, procurement, data-sharing constraints, pilot criteria.",
         deps="None", ac=["10+ interviews logged (anonymised)", "Synthesis with patterns and disconfirming evidence", "Named pilot-candidate shortlist"],
         source="Master prompt §8.", safety="Store notes without personal data beyond consent."),

    dict(id=20, pri="P1", phase="3–6 months", ws=["Commercial", "Product"], owner="BIZ",
         title="[P1] Design-partner pilot plan",
         problem="A pilot without baseline and exit criteria produces no evidence.",
         impl="Written plan: sponsor, scope, allowed data, baseline, success metrics, privacy/security gates, timeline, exit criteria, paid continuation path.",
         deps="#16, #17, #19", ac=["Plan reviewed by a prospective partner", "Measurable gates defined", "Legal/privacy review step included"],
         source="Board import.", safety="Deployment-specific POPIA assessment required."),

    dict(id=21, pri="P2", phase="6–12 months", ws=["Commercial"], owner="BIZ",
         title="[P2] Validate pilot price and annual licence",
         problem="Proposal figures (R270k six-month pilot, ~R600k/institution/year) are planning assumptions.",
         impl="Test against interview evidence, procurement cycles and a bottom-up cost model (cloud, data/feed licences, support, evaluation).",
         deps="#19, #20", ac=["Cost model", "Pricing supported by at least 3 buyer conversations", "Assumptions labelled"],
         source="Submitted proposal (team materials).", safety="—"),

    dict(id=22, pri="P2", phase="6–12 months", ws=["Security/Privacy", "Backend/API"], owner="DEVSEC",
         title="[P2] Enterprise deployment hardening",
         problem="Bank pilots require tenant isolation, access control and operational maturity.",
         impl="Tenant isolation, SSO/IAM, audit logs, observability, backups, incident response runbook, dependency scanning, external security review.",
         deps="#18", ac=["Repeatable deployment playbook", "Partner security review passed"],
         source="Board import.", safety="—"),

    dict(id=23, pri="P2", phase="6–12 months", ws=["Commercial"], owner="BIZ",
         title="[P2] Bottom-up TAM/SAM/SOM from named-account universe",
         problem="Proposal market sizes (TAM R151.2m, SAM R49.8m, SOM R3.6m) are not yet traceable.",
         impl="Named list of SA banks/fintechs/MSSPs from a cited official source x evidenced ACV ranges; show assumptions and sensitivity.",
         deps="#21", ac=["Every account and price traceable to a source or interview", "Low/base/high ranges"],
         source="Master prompt §8.", safety="—"),

    dict(id=24, pri="P2", phase="6–12 months", ws=["Commercial", "Product"], owner="BIZ",
         title="[P2] Define PMF and Series A readiness metrics",
         problem="No agreed definition of progress beyond the hackathon.",
         impl="Metric set: paid deployments, ARR, retention/expansion, pipeline, deployment time, unit economics, independent technical evidence, governance maturity — with current value (zero where zero) and targets.",
         deps="#23", ac=["Metrics doc with baselines and targets", "Reviewed quarterly"],
         source="Master prompt §2.", safety="Do not claim readiness until met."),

    # Added 2026-10-23 from build findings
    dict(id=25, pri="P0", phase="Hackathon", ws=["Threat Intelligence", "Backend/API"], owner="TL",
         title="[P0] Android platform CVE context from NVD API 2.0",
         problem="Analysts need vulnerability context for the device platform, kept separate from the malware verdict.",
         impl="Built: insider-threat-lab/app/mobile_risk/nvd.py: virtualMatchString on cpe:2.3:o:google:android:<version>, keeps CVEs where NVD marks Android vulnerable (exact/range), paging, rate-limit pauses, retries, 24h cache mounted into Docker, separate UI panel, VULN_CONTEXT_LOOKUP log event. Live: Android 13 gives 1,673 matches.",
         deps="#6", ac=["11 offline tests pass", "Live lookup verified in Docker", "UI states CVE is not malware and never alters the score", "NVD attribution shown"],
         source="Team request 2026-10-23; NVD API docs https://nvd.nist.gov/developers/vulnerabilities", safety="Exposure context only; no CVE never lowers risk."),

    dict(id=26, pri="P0", phase="Hackathon", ws=["ML", "Testing"], owner="DATA",
         title="[P0] Concept drift: 49% false-positive rate on newer benign apps",
         problem="On the per-class temporal split the baseline flags 49.1% of newer benign apps (precision 0.691). 65% of benign apps in the dataset are from 2011; threshold tuning on a temporal validation slice did not help (validation FPR 3.7%).",
         impl="Hackathon: present all three splits together and state the limitation. Post-event: add recent benign apps per Android version, re-run temporal evaluation, set a release gate on recent-benign FPR.",
         deps="#5", ac=["Drift result shown in UI, README and pitch", "Plan for recent benign data written", "FPR on newer apps re-measured after the data fix"],
         source="metrics.json split B", safety="Do not quote split A results alone."),

    dict(id=27, pri="P0", phase="Hackathon", ws=["Security/Privacy"], owner="DEVSEC",
         title="[P0] Disable Flask debug mode and fix session secret in container",
         problem="banking_app.py runs app.run(debug=True) inside Docker on 0.0.0.0:5000; the Werkzeug debugger allows code execution if reachable. The session secret is random per start, so every restart logs everyone out.",
         impl="Read the debug flag from env (default off); load SECRET_KEY from .env; keep placeholders in .env.example.",
         deps="None", ac=["Debug off by default in Docker", "SECRET_KEY from environment", "Sessions survive container restart"],
         source="Repository inspection 2026-10-23", safety="Do not expose port 5000 beyond localhost during the event."),

    dict(id=28, pri="P1", phase="Hackathon", ws=["Backend/API"], owner="DEVSEC",
         title="[P1] Fix log formatter errors on werkzeug/library log lines",
         problem="Root log format requires %(user)s and %(ip)s; werkzeug and library records lack them, producing 'Formatting field not found' errors in the container log.",
         impl="Add a logging.Filter that sets default user/ip on every record, or a dedicated handler for app security events.",
         deps="None", ac=["No logging errors on container start", "SOC log format unchanged for Logstash"],
         source="docker logs banking-app, 2026-10-23", safety="None."),

    dict(id=29, pri="P1", phase="Hackathon", ws=["Security/Privacy", "Documentation"], owner="TL",
         title="[P1] Stop tracking the application log file in git",
         problem="insider-threat-lab/logs/app/banking_app.log is tracked (included in commit 55b1123) and contains lab usernames and IPs.",
         impl="git rm --cached the log; .gitignore already covers *.log.",
         deps="None", ac=["Log no longer tracked", "Clean git status after running the app"],
         source="Repository inspection", safety="Logs can contain personal data in real deployments."),

    dict(id=30, pri="P1", phase="Hackathon", ws=["Security/Privacy", "Threat Intelligence"], owner="DEVSEC",
         title="[P1] Wazuh alerts not reaching Elasticsearch; Wazuh API refusing TLS",
         problem="wazuh-manager filebeat targets host wazuh.indexer, which is not in docker-compose.yml, so Wazuh alerts never reach Elasticsearch/Kibana. https://localhost:55000 fails the TLS handshake.",
         impl="Point filebeat at the compose elasticsearch service (or add a Wazuh indexer), check the API certificate, document. Decide whether Wazuh is in demo scope.",
         deps="SEC (regenerate the tracked Wazuh key first)", ac=["Wazuh alerts visible in Kibana", "API reachable or explicitly marked out of scope"],
         source="docker logs wazuh-manager, 2026-10-23", safety="Use regenerated keys, never the committed one."),

    dict(id=31, pri="P0", phase="Hackathon", ws=["Pitch", "Testing"], owner="FS",
         title="[P0] Demo readiness: warm NVD cache and rehearse the click path",
         problem="The first NVD lookup per Android version takes about 6 minutes without an API key; Docker Desktop has already stopped the stack once.",
         impl="Warm the cache for versions shown (NVD_CACHE_DIR=../nvd_cache python -m mobile_risk.nvd 13.0 14.0); request an NVD API key; raise Docker memory; rehearse: login, BlueWatch Mobile, 6 samples, NVD panel, Kibana Discover for MOBILE_RISK_ASSESSMENT.",
         deps="#7, #25", ac=["Full click path runs in under 90 s", "Fallback screen recording saved"],
         source="Build notes 2026-10-23", safety="Lab credentials only on screen."),

    dict(id=32, pri="P1", phase="0–30 days", ws=["Commercial", "Product"], owner="BIZ",
         title="[P1] Business, integration and licensing model write-up",
         problem="Judges and buyers will ask how banks with existing SOCs integrate and pay.",
         impl="Draft: bluewatch-mobile/docs/BUSINESS_AND_INTEGRATION.md covering buyer value, integration paths (API, SIEM forwarding, SOAR webhook, self-hosted, SDK), training lifecycle, licence tiers, CVE-component uses. Validate with interviews (#19).",
         deps="#19", ac=["Each claim tagged Built / Planned / Assumption", "Pricing validated with at least 3 buyer conversations"],
         source="Team request 2026-10-23", safety="No compliance or efficacy claims beyond measured evidence."),

    dict(id=33, pri="P0", phase="0–30 days", ws=["Data", "Commercial"], owner="TL",
         title="[P0] Secure commercial rights to training data",
         problem="KronoDroid is released for research purposes; selling a model trained on it needs the author's permission or replacement data.",
         impl="Email the dataset author about commercial terms; in parallel, scope own benign/malware collection in an isolated lab and partner threat-intel licences.",
         deps="#2", ac=["Written permission or a replacement dataset plan", "Data register updated with commercial terms"],
         source="KronoDroid README (research purpose, citation required)", safety="No malware handling outside an isolated environment."),
]


def labels_for(i):
    return [i["pri"].lower(), "bluewatch-mobile"] + \
        ["ws:" + w.lower().replace("/", "-").replace(" ", "-") for w in i["ws"]] + \
        (["security"] if "Security/Privacy" in i["ws"] else [])


def milestone_for(i):
    return i.get("milestone") or PHASE_MILESTONE[i["phase"]]


# Current state, 2026-10-23 evening. Anything not listed: Ready (hackathon) or Backlog.
STATUS_NOW = {
    1: "In Progress", 2: "In Progress", 3: "Done", 4: "Done", 5: "Done", 6: "Done",
    7: "Review / Testing", 8: "Done", 10: "In Progress", 12: "Blocked", 13: "In Progress",
    18: "In Progress", 25: "Done", 26: "In Progress", 27: "Done", 28: "Done", 31: "In Progress",
    32: "In Progress",
    "SEC": "Blocked",
}


BOARD_STATUS = {"Backlog": "Backlog", "Ready": "Ready", "In Progress": "In progress",
                "Review / Testing": "In review", "Blocked": "Blocked", "Done": "Done"}
HACKATHON_TARGET = "2026-10-24"


def status_for(i):
    if i["id"] in STATUS_NOW:
        return STATUS_NOW[i["id"]]
    return "Ready" if i["phase"] == "Hackathon" else "Backlog"


def body(i):
    ac = "\n".join(f"- [ ] {a}" for a in i["ac"])
    return f"""**Priority:** {PRIORITY[i['pri']]} · **Phase:** {i['phase']} · **Workstream:** {', '.join(i['ws'])}
**Suggested owner (role):** {ROLES[i['owner']]}

### Problem / context
{i['problem']}

### Proposed implementation
{i['impl']}

### Dependencies
{i['deps']}

### Acceptance criteria
{ac}

### Source / requirement
{i['source']}

### Safety / data / licensing
{i['safety']}
"""


def export():
    with open(HERE / "issues.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Title", "Priority", "Phase", "Workstream", "Status", "Milestone",
                    "Labels", "Owner role", "Acceptance criteria", "Body", "Private"])
        for i in ISSUES:
            w.writerow([i["title"], PRIORITY[i["pri"]], i["phase"], "; ".join(i["ws"]),
                        status_for(i), milestone_for(i), ",".join(labels_for(i)),
                        ROLES[i["owner"]], " | ".join(i["ac"]), body(i), i.get("private", False)])
    md = [f"# {PROJECT_TITLE}\n",
          "Generated by `board.py export`. Not yet a live GitHub Project — run `board.py apply` once gh is authenticated.\n"]
    for i in ISSUES:
        md.append(f"\n---\n\n## {i['title']}\n\n**Status:** {status_for(i)} · "
                  f"**Milestone:** {milestone_for(i)}"
                  + (" · **Track privately — do not open as a public issue**" if i.get("private") else "")
                  + f"\n\n{body(i)}")
    (HERE / "ISSUES.md").write_text("".join(md), encoding="utf-8")
    print(f"wrote issues.csv and ISSUES.md ({len(ISSUES)} items)")


def gh(args, dry, capture=True):
    print("$ gh " + " ".join(a if len(a) < 80 else a[:77] + "..." for a in args))
    if dry:
        return ""
    for attempt in range(4):
        r = subprocess.run([GH, *args], capture_output=capture, text=True, encoding="utf-8")
        if r.returncode == 0:
            return r.stdout.strip()
        transient = any(t in r.stderr for t in ("timeout", "TLS handshake", "connection reset",
                                                 "EOF", "502", "503", "rate limit"))
        if not transient:
            break
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(r.stderr.strip())


def graphql(query, dry, **variables):
    args = ["api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        args += ["-F" if isinstance(v, (int, bool)) else "-f", f"{k}={v}"]
    out = gh(args, dry)
    return json.loads(out) if out else {}


def ensure_status_options(project_id, fields, dry):
    """Add 'Blocked' to board 3's Status field, keeping its existing options."""
    status = fields["Status"]
    names = [o["name"] for o in status["options"]]
    if "Blocked" in names:
        return
    colors = {"Backlog": "GRAY", "Ready": "BLUE", "In progress": "YELLOW", "Blocked": "RED",
              "In review": "PURPLE", "Done": "GREEN"}
    wanted = ["Backlog", "Ready", "In progress", "Blocked", "In review", "Done"]
    wanted += [n for n in names if n not in wanted]
    opts = ",".join(f'{{name:"{n}",color:{colors.get(n, "GRAY")},description:""}}' for n in wanted)
    graphql(f"""mutation {{ updateProjectV2Field(input: {{fieldId: "{status['id']}",
            singleSelectOptions: [{opts}]}}) {{ projectV2Field {{ ... on ProjectV2SingleSelectField {{ id }} }} }} }}""",
            dry)


def apply(dry):
    # Labels and milestones
    existing_labels = [] if dry else [l["name"] for l in json.loads(
        gh(["label", "list", "--repo", REPO, "--limit", "200", "--json", "name"], dry))]
    for name, color in LABELS.items():
        if name not in existing_labels:
            gh(["label", "create", name, "--repo", REPO, "--color", color], dry)
    existing_ms = [] if dry else [m["title"] for m in json.loads(
        gh(["api", f"repos/{REPO}/milestones?state=all&per_page=100"], dry))]
    for title, due, desc in MILESTONES:
        if title in existing_ms:
            continue
        args = ["api", f"repos/{REPO}/milestones", "-f", f"title={title}", "-f", f"description={desc}"]
        if due:
            args += ["-f", f"due_on={due}"]
        gh(args, dry)

    # Issues (reuse by title)
    existing = {} if dry else {x["title"]: x["url"] for x in json.loads(
        gh(["issue", "list", "--repo", REPO, "--state", "all", "--limit", "500",
            "--json", "title,url"], dry))}
    issues = []
    for i in ISSUES:
        if i.get("private"):
            print(f"  skip (track privately): {i['title']}")
            continue
        url = existing.get(i["title"])
        if not url:
            url = gh(["issue", "create", "--repo", REPO, "--title", i["title"], "--body", body(i),
                      "--milestone", milestone_for(i),
                      *sum([["--label", l] for l in labels_for(i)], [])], dry)
        issues.append((i, url))
    if dry:
        print(f"... then link repo, add {len(issues)} items to project {PROJECT_NUMBER} and set fields")
        return

    # Project 3: link repo, add fields, add items, set fields
    gh(["project", "link", PROJECT_NUMBER, "--owner", OWNER, "--repo", REPO], dry)
    proj = json.loads(gh(["project", "view", PROJECT_NUMBER, "--owner", OWNER, "--format", "json"], dry))

    def load_fields():
        return {f["name"]: f for f in json.loads(gh(["project", "field-list", PROJECT_NUMBER, "--owner",
                                                     OWNER, "--format", "json"], dry))["fields"]}
    fields = load_fields()
    for name, opts in [("Phase", PHASES), ("Workstream", WORKSTREAMS)]:
        if name not in fields:
            gh(["project", "field-create", PROJECT_NUMBER, "--owner", OWNER, "--name", name,
                "--data-type", "SINGLE_SELECT", "--single-select-options", ",".join(opts)], dry)
    fields = load_fields()
    ensure_status_options(proj["id"], fields, dry)
    fields = load_fields()

    items = {it["content"]["url"]: it["id"] for it in json.loads(
        gh(["project", "item-list", PROJECT_NUMBER, "--owner", OWNER, "--format", "json",
            "--limit", "500"], dry))["items"] if it.get("content", {}).get("url")}

    def set_select(item_id, name, value):
        f = fields.get(name)
        opt = next((o for o in (f or {}).get("options", []) if o["name"] == value), None)
        if not opt:
            print(f"  (no option {name}={value})")
            return
        gh(["project", "item-edit", "--id", item_id, "--project-id", proj["id"],
            "--field-id", f["id"], "--single-select-option-id", opt["id"]], dry)

    for i, url in issues:
        item_id = items.get(url) or json.loads(gh(["project", "item-add", PROJECT_NUMBER, "--owner", OWNER,
                                                   "--url", url, "--format", "json"], dry))["id"]
        set_select(item_id, "Status", BOARD_STATUS[status_for(i)])
        set_select(item_id, "Priority", i["pri"])
        set_select(item_id, "Phase", i["phase"])
        set_select(item_id, "Workstream", i["ws"][0])
        if i["phase"] == "Hackathon" and "Target date" in fields:
            gh(["project", "item-edit", "--id", item_id, "--project-id", proj["id"],
                "--field-id", fields["Target date"]["id"], "--date", HACKATHON_TARGET], dry)
        print(f"  {status_for(i):<16} {url}")
    print(f"project: {proj.get('url')}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "export"
    if cmd == "export":
        export()
    elif cmd == "apply":
        apply(dry="--dry-run" in sys.argv)
    else:
        sys.exit(__doc__)
