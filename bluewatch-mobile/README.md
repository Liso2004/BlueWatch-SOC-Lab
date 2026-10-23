# BlueWatch Mobile — Android app risk triage (YES AI Hackathon 2026, Challenge 3)

Prototype, not a production malware-protection product. It scores pre-extracted Android app
features and gives a SOC analyst a risk score with supporting evidence. A human decides what
happens next; nothing here blocks accounts or devices.

## Status (23 Oct 2026)

| Component | Status | Where |
|---|---|---|
| Data preparation (KronoDroid real-device) | Implemented, run | `ml/prepare.py` |
| Random Forest baseline + 3-split evaluation | Implemented, run | `ml/train.py` → `insider-threat-lab/app/mobile_risk/artifacts/` |
| Inference API (Flask blueprint, login-protected) | Implemented, tested (16 tests) | `insider-threat-lab/app/mobile_risk/` |
| Analyst page `/mobile-risk` | Implemented; not yet clicked through in a browser | `insider-threat-lab/app/templates/mobile_risk.html` |
| SOC logging (`MOBILE_RISK_ASSESSMENT` → existing ELK/Wazuh log) | Implemented, tested | same log as banking app |
| Six labelled demo cases | Run, all six match their dataset label | `evidence/demo_cases.md` |
| Docker image with model runtime | Configured, **not yet built** | `insider-threat-lab/app/dockerfile` |
| Android on-device collector | Planned — not started | — |
| Threat-intelligence enrichment (NVD/MISP) | Planned — not started | — |
| Model registry / staged retraining | Planned — not started | — |

## How it fits the existing SOC Lab

BlueWatch SOC Lab (Jan 2026, pre-existing) is a Flask/MySQL banking app with ELK and Wazuh.
BlueWatch Mobile was added during the hackathon as a module inside that app: an analyst logs
in, opens **BlueWatch Mobile — Android App Risk** from the dashboard, scores an app, and each
assessment is written to the same security log that Logstash and Wazuh already ingest.

## Data

- **Source:** KronoDroid real-device v1 — https://github.com/aleguma/kronodroid (files
  `real_legitimate_v1.zip`, `real_malware_v1.zip`, retrieved 2026-10-23; SHA-256 in
  `insider-threat-lab/app/mobile_risk/artifacts/metrics.json`).
- **Citation (required by the dataset author):** A. Guerra-Manzanares, H. Bahsi, S. Nõmm,
  "KronoDroid: Time-based Hybrid-featured Dataset for Effective Android Malware Detection and
  Characterization", *Computers & Security* 110 (2021) 102399,
  https://doi.org/10.1016/j.cose.2021.102399
- **Terms:** released publicly "for research purpose" with the citation condition (dataset
  README). Commercial use beyond research needs the author's permission — open item.
- **What is used:** pre-extracted CSV features only (289 system-call counts, permissions,
  manifest counts). No APKs, no malware binaries, no personal data. Raw files are git-ignored.
- **Excluded from training to prevent label leakage:** `Detection_Ratio`, `Scanners`,
  `TimesSubmitted` (antivirus metadata), `MalFamily`, `Package`, `sha256`, dates.
- **After cleaning:** 76,708 apps (35,778 benign, 40,930 malware, 235 families), 475 features,
  dated 2008–2020. Dropped: 1,421 invalid dates, 8 hashes with conflicting labels.

## Model and measured results

`sklearn.ensemble.RandomForestClassifier` (scikit-learn 1.9.1; 150 trees, max depth 25,
balanced class weights, seed 42). Threshold 0.5. The score is the fraction of trees voting
"malware" — an uncalibrated risk score, **not a probability**.

| Split | Test n | Precision | Recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|---|
| A — random stratified 80/20 (**deployed model**) | 15,342 | 0.982 | 0.966 | 0.974 | 2.0% | 0.997 |
| B — per-class temporal 80/20 (newest 20% of each class) | 15,342 | 0.691 | 0.963 | 0.805 | **49.2%** | 0.976 |
| C — unseen malware families | 20,950 | 0.989 | 0.930 | 0.959 | 2.0% | 0.996 |

Source of truth: `insider-threat-lab/app/mobile_risk/artifacts/metrics.json`. Quote these
together — never split A alone.

## Known limitations

1. **Concept drift is severe.** Trained on older apps, the model flags ~half of newer benign
   apps (split B). 65% of benign apps in the dataset (23,085 of 35,778) are dated 2011, while malware peaks 2012–2018,
   so the model partly learns app era. Tuning the threshold on a temporal validation slice
   did not fix it (validation FPR 3.7% vs test 49%). This is the core problem the product must
   solve with recent benign data and governed retraining.
2. **Mostly static signal.** The most important features are permissions and manifest counts
   (`READ_PHONE_STATE`, `SEND_SMS`, permission totals); system calls contribute less. It is a
   hybrid static/dynamic model, not purely behavioural.
3. **Research dataset ≠ device telemetry.** Features came from instrumented collection; a
   non-root Android app cannot observe system calls directly. Collector feasibility is unproven.
4. **Six demo cases show the workflow, not efficacy.** All three benign demo samples are
   2011 apps — the era the model handles best.
5. **Evidence is not explanation.** The evidence table ranks features by model importance ×
   distance from the benign median; it is supporting context, not causal attribution.

## Reproduce (commands tested on Windows, Python 3.14.2)

```bash
pip install -r insider-threat-lab/app/requirements.txt pytest
mkdir -p bluewatch-mobile/data/raw && cd bluewatch-mobile/data/raw
curl -LO https://raw.githubusercontent.com/aleguma/kronodroid/main/real_device/real_legitimate_v1.zip
curl -LO https://raw.githubusercontent.com/aleguma/kronodroid/main/real_device/real_malware_v1.zip
cd ../../..
python bluewatch-mobile/ml/prepare.py          # ~20 s
python bluewatch-mobile/ml/train.py            # ~40 s, writes artifacts
python -m pytest insider-threat-lab/app/tests  # 16 tests
docker compose up -d --build banking-app mysql # then http://localhost:5000 → login → dashboard
```

The Docker step has not been run yet (Docker daemon was not running during the build).

## Responsible use

- Decision support only; the UI and every API response say so.
- No credentials, OTPs, message bodies or personal data are collected or used.
- Model, features and dataset versions are returned with every assessment and logged.
- No POPIA-compliance claim; a real deployment needs a privacy and legal assessment.

## AI-assisted development (to be completed by the team)

- **Claude Code (Anthropic, Claude Opus 5.5)** — used on 2026-10-23 for repository audit,
  secret scanning, project-board generation, and writing `ml/prepare.py`, `ml/train.py`,
  `mobile_risk/`, the analyst page, tests and this README. Reviewed and accepted by: _team to
  confirm_.
- **ChatGPT / Codex** — disclosed in the application; _team to confirm actual use in this repo_.
