# BlueWatch Mobile — scope check and freeze (23 Oct 2026, 18:00 SAST)

Checked against: the team master prompt (§3 product framing, §6 architecture, §9 deliverables,
§10 "freeze scope until one end-to-end sample works"), the hackathon P0 list on the board, and
the staged `BLUEWATCH_AI_PROJECT_ROADMAP_REVISED.md`.

**Decision: feature freeze now.** The end-to-end flow works (see `architecture.svg`). Until the
video is uploaded (Sat 24 Oct, 07:00 SAST) and the pitch is done, only the "remaining P0" items
below are worked on. No new features.

## 1. In scope and done

| Requirement (source) | State |
|---|---|
| Dataset with known source, terms, labels (P0 #2) | Done for hackathon; commercial rights open (#33) |
| Reproducible preprocessing, leakage checks (P0 #4) | Done |
| Baseline model + held-out metrics, incl. drift (P0 #5) | Done |
| Inference API with validation and tests (P0 #6) | Done |
| Analyst screen showing real results (P0 #7) | Done; visual click-through still to rehearse |
| 3 malicious + 3 benign end-to-end cases (P0 #8) | Done |

## 2. Added beyond the P0 list — keep, but frozen

| Addition | Why it stays | Freeze rule |
|---|---|---|
| NVD CVE context (#25) | Requested by the team; in the proposal architecture as threat-intel context | No more feeds (KEV/EPSS/MISP) before judging |
| API v1 with API keys (#34) | It is the integration story in the pitch | No rate limiting, OpenAPI, SIEM formats now |
| Audit store + analyst feedback (#34) | Supports "human review" and "feedback becomes labels" claims | No retraining from feedback now |
| Business/integration write-up (#32) | Investors and judges will ask | Planned items stay labelled Planned |

These are real and tested, but they were not needed for the minimum demo. The video should show
them in under 20 seconds; the demo is about the detection flow.

## 2b. Corrections after checking the organiser documents (23 Oct, 19:00)

The Master Operational Document (§1.2, §3.1 rubric, §3.3 pitch rules), the Pitch Instructions and
the team's POC technical brief were read in full. Four deviations were found and corrected:

| Deviation | Source | Correction |
|---|---|---|
| No Generative AI, but the rubric scores “Effective use of Generative AI” and “AI integration and execution” (criterion 5) | Master doc §3.1 | Claude-written analyst case brief with a grounding check and template fallback (`mobile_risk/genai.py`); never changes the score |
| Deck had 8 slides; pitch is “strictly … maximum 3 slides” | Master doc §3.3; Pitch Instructions | Cover and appendices hidden (backup for Q&A only); slides renamed to the suggested structure |
| Evidence showed mostly permissions; the brief asks for behavioural features (accessibility, overlay, SMS/notification, dynamic code, network, system calls) | POC technical brief | Behaviour profile in every result; new evaluation using runtime behaviour only (precision 0.969, recall 0.891) |
| README disclosure incomplete | Master doc §1.2 | `DISCLOSURE.md` completed from verified facts, team items marked |

Still open: rubric criterion 6 scores relevance to **youth employment / socio-economic impact**
(4% + 2%). The pitch states socio-economic impact (safer mobile banking) but not a youth
employment angle — the team must supply its real one; nothing has been invented.

## 3. Out of scope — parked

| Item | Why parked |
|---|---|
| Wazuh repair (#30) | Pre-existing SOC Lab; Kibana already shows BlueWatch events |
| `BLUEWATCH_AI_PROJECT_ROADMAP_REVISED.md` (LLM triage of SOC events, MITRE mapping, separate FastAPI AI service) | A different product (SOC alert triage), not Challenge 3. Keep it out of the pitch; decide after the event whether it is a separate track |
| React/TypeScript dashboard | Server-rendered page is enough for the demo |
| Android collector/SDK, iOS | Feasibility work, post-event |
| Six extra CVE use cases in the business doc | Ideas for investors, labelled Planned — not to be built now |

## 4. Where the build differs from the proposal (must be disclosed, not hidden)

| Proposal said | Built | Say in README/pitch |
|---|---|---|
| FastAPI service | Flask blueprint inside the SOC Lab app | "API built in Flask, reusing our existing lab" |
| PostgreSQL for audit/metadata | SQLite file | "Lightweight audit store; production database later" |
| React + TypeScript + Tailwind dashboard | Server-rendered HTML page | "Analyst screen; full dashboard later" |
| XGBoost as a candidate | Random Forest only | "Random Forest baseline; other models only if they beat the drift test" |
| Threat-intel ingestion with staging | NVD lookup only, context-only | "CVE context today; feeds and staging planned" |

## 5. Remaining P0 work, in order

1. **Video** (#9) — record and upload before 07:00; follow organiser timing.
2. **Demo readiness** (#31) — warm NVD cache, rehearse the click path, fallback recording.
3. **Rotate exposed secrets** (SEC, #12) — before anything is pushed.
4. **Commit** today's work to `Feature/Bluewatch-ai` (no push until secrets are rotated).
5. **README disclosure** (#10) — AI tools actually used, the differences in section 4, pre-existing vs new work.
6. **Live pitch rehearsal** (#11) — 3 slides, 5 minutes, Q&A bank.
7. **Evidence pack** (#13) — commit SHA, data hash, model version, metrics, screenshots.
