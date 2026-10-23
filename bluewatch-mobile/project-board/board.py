#!/usr/bin/env python3
"""
BlueWatch Mobile project board: single source of truth for issues, labels,
milestones and Projects v2 fields.

    python board.py export            # write issues.csv + ISSUES.md (no network)
    python board.py apply --dry-run   # print every gh call without running it
    python board.py apply             # create labels, milestones, issues, project

`apply` needs the GitHub CLI authenticated with the `project` scope:
    gh auth login && gh auth refresh -s project
It is idempotent on issue titles and label/milestone names. Not yet run against
GitHub - review the dry run first.
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

REPO = "Liso2004/BlueWatch-SOC-Lab"
OWNER = "Liso2004"
PROJECT_TITLE = "BlueWatch Mobile — YES AI Hackathon & Product Roadmap"
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
         impl="Model registry with versions, staging -> evaluation -> approval -> release, rollback. TI sources (NVD https://nvd.nist.gov/, MISP https://www.misp-project.org/) staged with provenance and licence; used as context, not as a malware verdict. Mark unbuilt parts Planned.",
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
]


def labels_for(i):
    return [i["pri"].lower(), "bluewatch-mobile"] + \
        ["ws:" + w.lower().replace("/", "-").replace(" ", "-") for w in i["ws"]] + \
        (["security"] if "Security/Privacy" in i["ws"] else [])


def milestone_for(i):
    return i.get("milestone") or PHASE_MILESTONE[i["phase"]]


def status_for(i):
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
    print("$ gh " + " ".join(args))
    if dry:
        return ""
    r = subprocess.run(["gh", *args], capture_output=capture, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def apply(dry):
    # Labels and milestones
    for name, color in LABELS.items():
        gh(["label", "create", name, "--repo", REPO, "--color", color, "--force"], dry)
    existing_ms = [] if dry else [m["title"] for m in json.loads(
        gh(["api", f"repos/{REPO}/milestones?state=all&per_page=100"], dry))]
    for title, due, desc in MILESTONES:
        if title in existing_ms:
            continue
        args = ["api", f"repos/{REPO}/milestones", "-f", f"title={title}", "-f", f"description={desc}"]
        if due:
            args += ["-f", f"due_on={due}"]
        gh(args, dry)

    # Project and custom fields
    if dry:
        project_num = "<N>"
    else:
        projects = json.loads(gh(["project", "list", "--owner", OWNER, "--format", "json"], dry))["projects"]
        match = [p for p in projects if p["title"] == PROJECT_TITLE]
        project_num = str(match[0]["number"]) if match else \
            str(json.loads(gh(["project", "create", "--owner", OWNER, "--title", PROJECT_TITLE,
                               "--format", "json"], dry))["number"])
        gh(["project", "link", project_num, "--owner", OWNER, "--repo", REPO], dry)
    for name, opts in [("Priority", list(PRIORITY.values())), ("Phase", PHASES),
                       ("Workstream", WORKSTREAMS), ("Board Status", STATUS)]:
        try:
            gh(["project", "field-create", project_num, "--owner", OWNER, "--name", name,
                "--data-type", "SINGLE_SELECT", "--single-select-options", ",".join(opts)], dry)
        except RuntimeError as e:
            print(f"  (field {name}: {e})")

    # Issues
    existing = [] if dry else [x["title"] for x in json.loads(
        gh(["issue", "list", "--repo", REPO, "--state", "all", "--limit", "500", "--json", "title"], dry))]
    created = []
    for i in ISSUES:
        if i.get("private"):
            print(f"  skip (track privately): {i['title']}")
            continue
        if i["title"] in existing:
            print(f"  exists: {i['title']}")
            continue
        url = gh(["issue", "create", "--repo", REPO, "--title", i["title"], "--body", body(i),
                  "--milestone", milestone_for(i), *sum([["--label", l] for l in labels_for(i)], [])], dry)
        created.append((i, url))

    # Add to project and set fields
    if dry:
        for i, _ in created:
            print(f"$ gh project item-add {project_num} ... + item-edit Priority/Phase/Workstream/Board Status")
        return
    proj = json.loads(gh(["project", "view", project_num, "--owner", OWNER, "--format", "json"], dry))
    fields = json.loads(gh(["project", "field-list", project_num, "--owner", OWNER,
                            "--format", "json"], dry))["fields"]
    fmap = {f["name"]: f for f in fields}

    def set_field(item_id, name, value):
        f = fmap.get(name)
        opt = next((o for o in (f or {}).get("options", []) if o["name"] == value), None)
        if not opt:
            print(f"  (no option {name}={value})")
            return
        gh(["project", "item-edit", "--id", item_id, "--project-id", proj["id"],
            "--field-id", f["id"], "--single-select-option-id", opt["id"]], dry)

    for i, url in created:
        item = json.loads(gh(["project", "item-add", project_num, "--owner", OWNER,
                              "--url", url, "--format", "json"], dry))
        set_field(item["id"], "Priority", PRIORITY[i["pri"]])
        set_field(item["id"], "Phase", i["phase"])
        set_field(item["id"], "Workstream", i["ws"][0])
        set_field(item["id"], "Board Status", status_for(i))
        print(f"  {url}")
    print(f"project: {proj.get('url')}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "export"
    if cmd == "export":
        export()
    elif cmd == "apply":
        apply(dry="--dry-run" in sys.argv)
    else:
        sys.exit(__doc__)
