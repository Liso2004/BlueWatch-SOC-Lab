# BlueWatch Mobile — Value, Integration, Model Training and Business Model

*Draft, 23 Oct 2026. Every item is tagged **Built** (in this repo, tested), **Planned** (not
built) or **Assumption** (needs evidence). Numbers come only from
`insider-threat-lab/app/mobile_risk/artifacts/metrics.json` or are marked as assumptions.*

---

## 0. Android-first, by design

BlueWatch Mobile targets **Android devices first; iPhone (iOS) is a later phase.**

- **That is where the customers are.** Android runs on about 76% of smartphones in South
  Africa; iOS on about 24% (StatCounter, mobile OS share, June 2026:
  https://gs.statcounter.com/os-market-share/mobile/south-africa).
- **That is where banking malware works.** Android lets apps draw screens over other apps,
  use accessibility services to read the screen and act for the user, and be installed from a
  link outside the Play Store. Recent Android banking-trojan research describes campaigns built
  on exactly these: overlays, accessibility abuse and sideloaded fake apps (vendor research from
  Zimperium, Cleafy and Verimatrix, 2024–26, via secondary reporting; primary reports to be
  cited before external publication). Android accessibility API:
  https://developer.android.com/guide/topics/ui/accessibility/service
- **iPhones restrict these capabilities**, so the same attack paths are harder there; iOS would
  need a different signal set and is not in the current scope.
- **Our model and data are Android-only** (KronoDroid Android apps; Android CVEs from NVD).

## 1. Who benefits, and how — for organisations that already have a security team

BlueWatch Mobile does not replace a bank's SOC, fraud platform, mobile threat defence or
antivirus. It adds one thing those teams often lack: **a scored, evidence-backed view of risky
Android apps and devices, delivered into the tools they already use.**

| Buyer | Their current problem (to validate in interviews) | What BlueWatch adds |
|---|---|---|
| **Bank SOC / security operations** | Mobile banking malware is investigated after fraud happens; Android app behaviour is not visible in the SIEM | App-risk events with evidence, model version and timestamps, in the SIEM they already run (**Built**: events reach Elasticsearch/Kibana today) |
| **Fraud & financial-crime teams** | Account-takeover cases where the device was compromised by an overlay/SMS-stealing app | A device/app risk signal to combine with transaction risk, e.g. step-up authentication instead of a block (**Planned**) |
| **Mobile app security / AppSec** | Need to know which Android OS versions their customers run that carry critical CVEs | Android platform CVE exposure by version, from NVD (**Built** for OS versions) |
| **MSSPs / security integrators** | Serve several mid-size banks/fintechs; need multi-tenant detections they can resell | Per-tenant licence and API (**Planned**) |
| **Fintechs without a large SOC** | No in-house malware analysts | Hosted triage with clear "review / no review" output (**Planned**) |

**Why existing teams would adopt it**
1. **It fits current workflow.** Output is a log event and an API response, not another console analysts must watch.
2. **It is explainable.** Each result carries evidence features, the banking-related capabilities present (overlay, accessibility, SMS, notification access, device admin), model and feature versions — enough for an analyst to justify escalation.
3. **It keeps humans in control.** Scores are "prioritise for review", never an automatic account block. This matters for customer fairness and regulatory scrutiny.
4. **It is honest about limits.** We show our own drift result (below) instead of a single headline accuracy number — the kind of evidence a bank's model-risk team will ask for.

---

## 2. How it integrates

| Integration path | How it works | Status |
|---|---|---|
| **REST API** | `POST /api/mobile/assess` with app features → verdict, risk score, evidence, model version. `GET /api/mobile/vulnerabilities?android_version=13.0` → CVE context. | **Built** (session-authenticated inside the lab app). **Planned for production:** API keys / OAuth2 client credentials, mTLS, rate limits, OpenAPI spec, versioned `/v1/` paths |
| **SIEM log forwarding** | Every assessment and CVE lookup is written as a structured log line (`MOBILE_RISK_ASSESSMENT`, `VULN_CONTEXT_LOOKUP`) with user, IP, model version | **Built** — ingested by Logstash into Elasticsearch/Kibana. **Planned:** JSON/ECS and CEF/syslog output for Splunk, Microsoft Sentinel, IBM QRadar |
| **SOAR / case management webhook** | Push high-risk results to the bank's ticketing or SOAR playbook | **Planned** |
| **Self-hosted container** | Bank runs BlueWatch inside its own network/VPC; no customer data leaves | **Built** as Docker image for the lab; **Planned:** hardened image, Helm chart, air-gapped model updates |
| **Mobile SDK in the bank's own app** | Bank's Android app collects a minimal, consented feature set and sends it to BlueWatch | **Planned — feasibility unproven.** A non-root app cannot see system calls; we must first map which signals Android actually allows (board item: collector feasibility) |

**Recommended first customer integration (pilot):** self-hosted container + SIEM log forwarding +
REST API. It needs no change to the customer's mobile app and keeps data inside the bank.

Data flow, today and planned:

```
App features (dataset today; SDK/collector later)
        │
        ▼
 BlueWatch API ──► ML risk score + evidence ──┐
        │                                     ├──► Analyst UI / SIEM / SOAR ──► human decision
        └──► NVD CVE context (separate) ──────┘
             (never changes the ML score)
```

---

## 3. How the models are trained

### 3.1 What exists now (Built)

| Step | Detail |
|---|---|
| Data | KronoDroid real-device v1 (research dataset, 2008–2020): 76,708 apps after cleaning — 35,778 benign, 40,930 malware, 235 families |
| Features | 475: system-call counts (behavioural), permissions, manifest/component counts |
| Leakage control | Removed antivirus scan results, family names, package names, hashes and dates from training inputs; dropped 8 hashes with conflicting labels |
| Model | scikit-learn Random Forest, 150 trees, fixed seed — reproducible with `prepare.py` + `train.py` (~1 minute total) |
| Evaluation | Three held-out tests, all reported together (below) |
| Versioning | Model, feature-set and dataset hashes returned with every prediction and logged |

| Held-out test | Precision | Recall | False-positive rate |
|---|---|---|---|
| Random 80/20 (deployed model) | 0.982 | 0.966 | 2.0% |
| Malware families never seen in training | 0.989 | 0.930 | 2.0% |
| **Newer apps, trained on older ones** | 0.691 | 0.963 | **49.1%** |

**Key finding:** the model generalises to unseen malware *families* but **not to newer
benign apps** — it flags about half of them. Most benign training apps date from 2011. This
is concept drift, and it is the central technical problem the product must solve.

### 3.2 How training must work in the product (Planned)

1. **Recent, rights-cleared benign data.** Collect current benign apps (top banking, payment and popular apps by Android version) — the fastest fix for the 49% false-positive problem.
2. **Licensed or self-collected malware data.** KronoDroid is released for research; **commercial use needs the author's permission or our own data.** Options: licence agreement, partner threat-intel feeds, sandboxed analysis in an isolated lab.
3. **Customer feedback labels.** Analyst decisions ("confirmed malicious / false positive") from pilots become labelled data — with customer agreement and data-minimisation rules.
4. **Temporal validation as a release gate.** Every new model is tested on apps newer than its training data; release only if false-positive rate on recent benign apps is below an agreed limit with the customer.
5. **Per-customer thresholds.** Banks choose the review threshold based on analyst capacity, measured in alerts per day.
6. **Model registry and rollback.** Staged releases (train → evaluate → approve → deploy), signed artefacts, one-step rollback.
7. **Drift monitoring.** Track score distributions and analyst override rates in production; alert when they shift.
8. **Possible later step:** gradient-boosted models or sequence models over system-call traces, *only if* they beat the baseline on the temporal test.

---

## 4. How the business makes money

### 4.1 Revenue model — licensing (recommended)

| Line | What the customer pays for | Status of price |
|---|---|---|
| **Paid pilot** | 6-month deployment, integration, evaluation report against the customer's baseline | **Assumption:** R270k (from submitted proposal) |
| **Annual platform licence** | Self-hosted or hosted BlueWatch, model updates, CVE context, support | **Assumption:** ~R600k per institution/year (from proposal) |
| **Tier by volume** | Banded by monitored apps/devices or assessments per month | To design after pilots |
| **Self-hosted premium** | Air-gapped/on-prem deployment, signed offline model updates | To design |
| **MSSP / reseller licence** | Multi-tenant licence; partner resells to its bank/fintech clients at a discount | To design |
| **Professional services** | Integration with the bank's SIEM/SOAR, custom thresholds, model validation reports for model-risk/audit teams | Day rate, to set |

**Why licence, not per-API-call only:** banks budget annually, prefer predictable cost and
often require self-hosting; per-call pricing suits fintechs and could be a second tier.

### 4.2 What must be true before these prices are credible

- 10–15 discovery interviews confirming the problem, buyer and budget owner (board item).
- At least one paid or co-funded pilot with written success criteria.
- A commercially usable training dataset (see 3.2 point 2) — **this is a hard blocker for selling.**
- Bottom-up market sizing from a named list of South African banks, fintechs and MSSPs. The proposal's TAM R151.2m / SAM R49.8m / SOM R3.6m are **unverified planning assumptions**.

### 4.3 Main costs to model

Cloud/hosting (if hosted), data and threat-intel licences, model retraining and evaluation,
security reviews and penetration tests, support staff, legal/privacy review per deployment.

---

## 5. Other uses of the CVE (NVD) component

Today the component answers one question: *which published CVEs does NVD say affect Android
version X?* (**Built**; live result for Android 13: 1,673 matching CVEs, 32 critical.) It is a
deterministic data service, not an AI agent. The same foundation supports:

| Use | Who buys it | What is needed | Status |
|---|---|---|---|
| **Customer-device risk for fraud** — older Android versions with critical unpatched CVEs trigger step-up authentication, not a block | Fraud teams | Device OS/patch level from the bank's app | Planned |
| **Employee/BYOD fleet exposure** — count staff devices per Android version and their critical CVEs | IT security, MDM teams | Export from the bank's MDM | Planned |
| **Patch and upgrade prioritisation** — rank exposure by severity and by whether a flaw is known to be exploited, using CISA's Known Exploited Vulnerabilities catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and FIRST EPSS scores (https://www.first.org/epss/) | Vulnerability management | Add KEV + EPSS feeds | Planned |
| **Third-party SDK risk in the bank's own app** — match the bank app's software bill of materials against NVD | AppSec, vendor risk | SBOM input, CPE/package matching | Planned |
| **Minimum-supported-OS policy evidence** — data to justify dropping old Android versions from the banking app | Product/AppSec, risk committees | Reporting view | Planned |
| **Board and regulator reporting** — periodic exposure summaries with sources and timestamps | CISO, risk, compliance | Scheduled reports | Planned |
| **Threat-intel enrichment in the SIEM** — attach CVE context to alerts already in Kibana/Splunk/Sentinel | SOC | Log/enrichment output | Partly built (logged lookups) |

**Rule that holds for every use:** a CVE shows *exposure*, not *compromise* or *malice*. No
CVE match never lowers malware risk, and CVE data never silently changes the ML score.
NVD attribution: "This product uses the NVD API but is not endorsed or certified by the NVD."
Review NVD terms of use before redistributing cached data commercially.

---

## 6. Open items before we pitch these claims

1. Commercial rights to training data (KronoDroid is research use).
2. Fix the newer-app false-positive rate with recent benign data, and re-measure.
3. Production authentication on the API (currently lab session login).
4. Collector feasibility — which Android signals a non-root app can legally and technically obtain.
5. Interviews and a pilot to replace pricing and market-size assumptions with evidence.
6. Regulatory mapping for South African banks (privacy and cyber-resilience requirements) — **to research and cite**; no compliance claim until assessed.
