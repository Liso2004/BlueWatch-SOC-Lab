# BlueWatch Mobile — reproducibility and evidence pack

Board #13. Everything the video, deck and Q&A claim should trace to a line here.
Status tags: **Implemented · Tested · Verified in Docker · Mocked · Planned.**

## 1. Versions

| Item | Value |
|---|---|
| Code | branch `Feature/Bluewatch-ai`; build commit `31f92ad`, README fixes `8c9135e`, `1991122` (local, not pushed) |
| Model | `bwm-rf-0.1.0` — scikit-learn 1.9.1 `RandomForestClassifier`, Python 3.14.2, trained on 61,366 rows, seed 42 |
| Features | `kronodroid-real-v1/features-1` — 475 features, schema `bluewatch-mobile/schema/features_v1.json` |
| Dataset | KronoDroid real-device v1, retrieved 23 Oct 2026 · `real_legitimate_v1.zip` SHA-256 `21f6d507…f782` (36,755 rows) · `real_malware_v1.zip` SHA-256 `03aa36a9…cb8cd` (41,382 rows) |
| After cleaning | 76,708 apps (35,778 benign, 40,930 malware, 235 families); dropped 1,421 invalid dates and 8 conflicting-label hashes |
| Reproduction | `prepare.py` → `train.py` re-creates the deployed model **byte-identically** (checked with `cmp`, 23 Oct) |

## 2. Held-out results (`insider-threat-lab/app/mobile_risk/artifacts/metrics.json`)

Threshold 0.5. Test sets never used in training.

| Split | Test n (benign / malware) | TP | FP | FN | TN | Precision | Recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| A random 80/20 (deployed) | 15,342 (7,156 / 8,186) | 7,904 | 143 | 282 | 7,013 | 0.982 | 0.966 | 0.974 | 2.0% | 0.997 |
| B newer apps (temporal) | 15,342 (7,156 / 8,186) | 7,880 | 3,517 | 306 | 3,639 | 0.691 | 0.963 | 0.805 | **49.1%** | 0.976 |
| C unseen malware families | 20,950 (7,156 / 13,794) | 12,827 | 140 | 967 | 7,016 | 0.989 | 0.930 | 0.959 | 2.0% | 0.996 |
| D runtime behaviour only (220 features) | 15,342 (7,156 / 8,186) | 7,295 | 233 | 891 | 6,923 | 0.969 | 0.891 | 0.929 | 3.3% | 0.984 |

**Leakage checks (recorded in `metrics.json`):** train/test SHA-256 overlap = **0** in all four
splits; malware-family overlap in split C = **0**. Antivirus metadata, family names, package
names, hashes and dates are excluded from model inputs.

## 3. End-to-end evidence

| Claim | Evidence | Status |
|---|---|---|
| 6 labelled samples (3 malware, 3 benign) run through the same path; 6/6 match labels | `evidence/demo_cases.md` | Tested |
| Analyst page, keyed API v1, audit store, feedback, behaviour profile | 58 automated tests (`insider-threat-lab/app/tests/`) | Tested, verified in Docker |
| Assessments and feedback reach the SIEM | `MOBILE_RISK_ASSESSMENT` events searchable in Kibana (19 on 23 Oct) | Verified in Docker |
| Android CVE context | NVD API 2.0, Android 13: 1,574 exact + 99 range matches (retrieved 23 Oct 13:44 UTC) | Verified in Docker |
| Grounded GenAI brief | Local model: 4/6 demo samples accepted in Docker, 2 fell back to template. Claude path tested with a fake client only — **needs `AI_API_KEY` to verify live** | Tested; Claude live **not yet verified** |
| API rejects missing/invalid keys | `API_AUTH_FAILED` logged; 401 verified in Docker | Verified in Docker |

## 4. Known limitations (say these, don’t hide them)

1. 49.1% false alarms on apps newer than the training data (split B).
2. Research dataset (2008–2020), research-use terms; commercial rights not yet obtained.
3. Features come from instrumented analysis; a non-root app cannot collect system calls — collector feasibility unproven.
4. Six demo samples show the workflow, not efficacy; all three benign demo samples are 2011 apps.
5. Evidence ranking is importance × deviation — context, not causal explanation.
6. Screen capture is not observable in this dataset.
7. Prototype only: no rate limiting, enterprise login or hardened deployment; credentials committed before the event still need rotating.

## 5. Planned (not claimed as built)

On-device collector / bank-app SDK · fresh Android data with commercial rights · newer-apps release gate · model registry and rollback · MISP / CISA KEV feeds · rate limiting, OpenAPI, SIEM-native formats · iOS · cross-bank shared model updates.

## 6. Still to add before judging

- [ ] Screenshots of the analyst page (verdict, behaviour profile, AI brief, feedback) and Kibana
- [ ] Video upload confirmation (board #9)
- [ ] Live Claude brief once a key is set
