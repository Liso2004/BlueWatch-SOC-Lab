# BlueWatch Mobile — AI, Data, API and Third-Party Disclosure

Required by the YES AI Hackathon 2026 Master Operational Document §1.2 (building on existing
work, third-party materials, generative AI tools, transparency). Items marked **[TEAM TO
CONFIRM]** could not be verified from the repository and must be completed by the team.

## 1. Project status and pre-existing work

BlueWatch Mobile is ImpactStack Africa's Challenge 3 prototype (Android Banking Malware
Detection Engine). It is a working prototype, not a production product.

- **Existed before the event (BlueWatch SOC Lab, commits 16–26 Jan 2026):** Flask/MySQL
  "SecureBank" lab app with login and customer APIs, insider-threat attack scripts, a statistical
  anomaly detector, ELK (Elasticsearch, Logstash, Kibana) and Wazuh in Docker Compose.
- **Created or changed during the event (23–24 Oct 2026):** everything under `bluewatch-mobile/`
  and `insider-threat-lab/app/mobile_risk/`, the analyst page `templates/mobile_risk.html`, tests
  in `insider-threat-lab/app/tests/`, and these changes to the lab app: environment-based
  secrets, debug mode off by default, log-format fix, blueprint registration, Python 3.14 image.
- **Not built (planned):** Android on-device collector, iOS, malware threat-intel feeds (MISP,
  CISA KEV), model registry with staged retraining, rate limiting, OpenAPI, cloud deployment.

## 2. AI-assisted development tools

| Tool / model | Use in this project | Team review |
|---|---|---|
| Claude Code (Anthropic), model Claude Opus 5.5 | 23 Oct 2026: repository audit and secret scan, project board generation, data preparation and training scripts, `mobile_risk` module (API, audit store, NVD client, GenAI brief, behaviour profile), analyst page, tests, documentation, architecture diagram, pitch deck draft | **[TEAM TO CONFIRM]** who reviewed and accepted each part |
| ChatGPT / OpenAI tools, Codex | Disclosed in the YES application for research, ideation, documentation and code assistance | **[TEAM TO CONFIRM]** whether used in this repository, and for what |

AI-assisted output is not treated as correct because a tool produced it: every number in the
pitch comes from `metrics.json`, and 52 automated tests cover the code.

## 3. AI/ML components in the product

| Component | What it is | Measured |
|---|---|---|
| Detection model | scikit-learn 1.9.1 `RandomForestClassifier` (150 trees, depth 25, balanced class weights, seed 42), version `bwm-rf-0.1.0`, 475 features | Random split: precision 0.982, recall 0.966, FPR 2.0% · unseen malware families: precision 0.989, recall 0.930 · **newer apps: precision 0.691, FPR 49.1%** · runtime behaviour only (220 system-call/network features): precision 0.969, recall 0.891, FPR 3.3% |
| Generative AI case brief | An LLM writes a 4–6 sentence brief from the assessment facts. Two providers: **free local model** `qwen2.5:1.5b` via Ollama (`AI_PROVIDER=ollama`; runs on the machine, no data leaves it) or **Claude** (`claude-opus-5-5` default) via the Anthropic Python SDK 2.2.0 (`AI_PROVIDER=anthropic` + `AI_API_KEY`) | Grounding check rejects any number not in the facts and claims such as "confirmed malware" or "block the customer"; fails back to a labelled template. The small local model fails the check more often than Claude — the fallback is shown to the analyst |
| Behaviour profile | Rule-based grouping of signals into the brief's categories (overlay, accessibility, SMS/notification, dynamic code, network, persistence, screen capture) | Context only; does not change the score |

- **Score meaning:** fraction of trees voting "malware" — an uncalibrated risk score, not a probability.
- **Decision boundary:** decision support only. Nothing blocks customers, accounts or devices.
- **Feature evidence:** model importance × distance from the benign median — supporting context, not causal explanation.

## 4. Datasets and data sources

| Source | Version / retrieved | Used | Terms | Limitations |
|---|---|---|---|---|
| KronoDroid real-device dataset — https://github.com/aleguma/kronodroid | `real_legitimate_v1.zip`, `real_malware_v1.zip`, retrieved 23 Oct 2026 (SHA-256 in `metrics.json`) | Pre-extracted CSV features only (system-call counts, permissions, manifest counts); no APKs or malware binaries | Released "for research purpose" on condition of citing Guerra-Manzanares, Bahsi & Nõmm, *Computers & Security* 110 (2021) 102399, doi:10.1016/j.cose.2021.102399. **Commercial use needs the author's permission** (board #33) | Apps dated 2008–2020; 65% of benign apps from 2011, causing the newer-app drift; features from instrumented collection, not what a non-root app can observe |
| CICMalDroid 2020 | — | Considered, not used | — | — |

No personal data, credentials, OTPs or message contents are used. Raw data is git-ignored.

## 5. APIs, frameworks and other software

| Component | Package / service and version | Purpose | Licence / terms |
|---|---|---|---|
| Web app and API | Flask 3.0.0 | Analyst page, `/api/mobile/*`, `/api/v1/mobile/*` | BSD-3-Clause |
| ML | scikit-learn 1.9.1, numpy 2.5.4, scipy 1.18.1, joblib 1.6.0 | Training and inference | BSD-3-Clause (numpy also bundles 0BSD/MIT/Zlib-licensed parts) |
| Generative AI | Anthropic Python SDK 2.2.0 → Claude API | Case brief | Apache-2.0 (SDK); Anthropic commercial terms (API) |
| Vulnerability data | NIST NVD CVE API 2.0 | Android OS CVE context | Public; "This product uses the NVD API but is not endorsed or certified by the NVD." |
| Audit store | SQLite (Python standard library) | Assessments and analyst feedback | Public domain |
| Lab stack (pre-existing) | MySQL 8.0, Elasticsearch/Logstash/Kibana 8.11.0, Wazuh manager 4.7.0, PyMySQL, bcrypt | Login, SIEM pipeline | Per vendor licences |
| Fonts in deck | Space Grotesk, IBM Plex Sans (Google Fonts) | Slides | SIL Open Font License |
| Hosting | Local Docker Compose only — **no cloud deployment** | — | — |

## 6. Third-party content

- **Code copied from others:** none known. **[TEAM TO CONFIRM]**
- **Market and threat statistics in the deck:** StatCounter (SA mobile OS share, June 2026);
  Android banking-trojan descriptions from Zimperium, Cleafy and Verimatrix research as reported
  by TechRepublic and Infosecurity Magazine (secondary sources).
- **Diagrams:** `docs/architecture.svg/png` drawn for this project; no third-party images.

## 7. Responsible AI, privacy and security

- Human decides; feedback labels never change scores automatically; retraining needs a reviewed export.
- Data minimisation: only app feature counts are stored or sent to Claude; no user identity is sent.
- API keys stored as SHA-256 hashes; secrets in `.env` (git-ignored); debug mode off by default.
- Known open security item: credentials and a Wazuh key committed to this public repo before the
  event must be rotated (board #12) **[TEAM TO CONFIRM when done]**.
- Not a claim of POPIA compliance; a real deployment needs a privacy and legal assessment.

## 8. Team contribution

- **Liso Wycliff Seth Hlatshwayo** — Founder / Technical Lead. **[TEAM TO CONFIRM specific contributions]**
- **Stacey-Lee Pietersen** — Full Stack / Prototype Engineer. **[TEAM TO CONFIRM]**
- YES-sponsored Cloud & DevSecOps and Data & MLOps roles — **[TEAM TO CONFIRM whether onboarded]**

## 9. Reproducibility

See `README.md` → *Reproduce*: download the two KronoDroid zips, `python bluewatch-mobile/ml/prepare.py`,
`python bluewatch-mobile/ml/train.py` (fixed seed; deployed model reproduces byte-identically),
`python -m pytest insider-threat-lab/app/tests` (52 tests), `docker compose up -d --build banking-app mysql`.
