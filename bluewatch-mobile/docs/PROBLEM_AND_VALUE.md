# BlueWatch Mobile — Problem, Solution, Progress and Value Proposition

*23 Oct 2026. Board #43. Evidence labels: **[verified]** read from the primary source ·
**[press]** reported by media, primary not verified · **[assumption]** to validate ·
**[built]** in the repo and tested · **[planned]** not built.*

---

## 1. Chosen problem

**YES AI Hub Challenge 3 — Android Banking Malware Detection Engine.**

Banking trojans on Android phones steal credentials and one-time passwords by abusing
legitimate Android features — screens drawn over the banking app, accessibility services that
read the screen and tap for the user, and SMS/notification access — and they change faster than
signature lists. Bank security teams usually learn about it after the money has gone.

## 2. Problem statements (one per beneficiary)

| Who | Problem statement |
|---|---|
| **Bank SOC analyst** | “When a customer’s account is taken over through their phone, I have no view of which app on that device behaved maliciously, so I investigate after the loss and cannot explain the cause.” |
| **Fraud / financial-crime team** | “At the moment of a transaction I have no signal that the customer’s device is compromised, so I either let fraud through or add friction for everyone.” |
| **Bank security leadership** | “Signature-based mobile tools miss new variants and their scores are opaque, so I cannot justify decisions to customers, auditors or the regulator.” |
| **Banking customer** | “I cannot tell that the ‘update’ I installed from a link is reading my SMS codes — I find out when my account is empty.” |

## 3. Research — what makes the problem real

| Finding | Source | Label |
|---|---|---|
| Android runs on ~76% of smartphones in South Africa; iOS ~24% (June 2026) | [StatCounter, SA mobile OS share](https://gs.statcounter.com/os-market-share/mobile/south-africa) | [verified via StatCounter page summary] |
| 162,275 mobile banking trojan installation packages detected in Q1 2026; banking trojans were 52.96% of detected malicious mobile apps | [Kaspersky Securelist, “IT threat evolution in Q1 2026. Mobile statistics”, 18 May 2026](https://securelist.com/malware-report-q1-2026-mobile-statistics/119819/) | [verified] |
| 34 active Android malware families targeted 1,243 financial institutions in 90 countries in 2025; Android-malware-driven financial transactions up 67% year on year | Zimperium 2026 Banking Heist Report, via [SC World](https://www.scworld.com/news/mobile-banking-trojans-expand-capabilites-66-now-allow-full-device-takeover) | [press] |
| 2025–26 campaigns rely on overlays, accessibility abuse and sideloaded fake apps (e.g. ToxicPanda, BingoMod) | [TechRepublic](https://techrepublic.com/article/news-android-malware-stealing-pin-overlay-attack), [Infosecurity Magazine](https://infosecurity-magazine.com/news/updated-toxicpanda-140-banking), [Verimatrix](https://www.verimatrix.com/cybersecurity/cybersecurity-insights/deconstructing-a-mobile-banking-app-overlay-heist/) | [press / vendor] |
| SA digital banking fraud rose sharply in 2024 and banking apps were the largest channel (reported counts conflict: ~64,000 vs ~98,000 incidents; losses ~R1.4bn vs ~R1.9bn) | SABRIC Annual Crime Statistics 2024 via [TechAfrica News](https://techafricanews.com/2025/08/29/south-africa-sees-86-surge-in-digital-banking-fraud-losses-near-r1-9-billion/), [BusinessTech](https://businesstech.co.za/news/banking/872745/alarm-bells-for-anyone-with-banking-apps-on-their-phones-in-south-africa/) | [press — primary PDF link returned 404; **do not quote figures in the pitch until the SABRIC report is read**] |
| Much reported SA app fraud is social engineering (PIN/OTP disclosure, SIM swap), not only malware | Same press coverage | [press] — scope note: BlueWatch addresses the malware/device-compromise part, not all app fraud |

### Applicable standards and frameworks
- **OWASP MASVS** (Mobile Application Security Verification Standard) — https://mas.owasp.org/MASVS/
- **NIST AI Risk Management Framework** — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- **Android platform security and accessibility-service documentation** — https://developer.android.com/privacy-and-security/about · https://developer.android.com/guide/topics/ui/accessibility/service
- **NIST NVD** for vulnerability context — https://nvd.nist.gov/
- **POPIA** (South Africa’s privacy law; Information Regulator https://inforegulator.org.za/) — deployment needs a privacy assessment; no compliance claim made.

## 4. The solution

**BlueWatch Mobile spots Android banking malware by what apps do, explains it in plain
language with AI that cannot invent facts, and puts the evidence in the tools a bank’s
security team already uses — with a human always deciding.**

| Layer | What it does | Status |
|---|---|---|
| Behavioural ML detection | Random Forest on 475 signals (system calls, network, permissions, manifest) → risk score + evidence | [built] |
| Behaviour profile | Evidence grouped by banking-malware technique; declared permissions kept separate from observed runtime behaviour | [built] |
| Grounded GenAI case brief | An LLM writes the analyst brief; a check rejects any number, permission name or claim not in the evidence, and any probability language | [built] — local model (free, on-premises) or Claude |
| Analyst decision loop | Confirm / false positive / missed malware → audited labels for reviewed retraining | [built] |
| Bank integration | Keyed API, SIEM events (Elasticsearch/Kibana today), Docker deployment inside the bank | [built] |
| Android CVE context | Known vulnerabilities per Android version from NIST NVD, never part of the score | [built] |

## 5. Where BlueWatch can be genuinely new (ground-breaking, stated honestly)

Not “better AI”. Four combinations that existing tools do not usually offer together:

1. **AI that is mechanically prevented from making things up.** Most GenAI security assistants
   rely on the prompt. BlueWatch checks every number, permission name and claim against the
   evidence and rejects the brief otherwise — covered by automated tests. **[built]**
2. **The whole AI stack runs inside the bank.** Detection model and the language model run
   on-premises (the free local model needs no cloud call), so no customer or device data leaves
   the bank — a direct answer to data-residency and privacy objections. **[built for the demo; production hardening planned]**
3. **Drift honesty as a product feature.** We publish our own failure case (49% false alarms on
   newer apps) and make a newer-apps test the release gate for every model. Opaque vendor scores
   cannot be audited this way. **[measured; release gate planned]**
4. **The bank’s own app as the sensor — no root, no extra app.** Android gives an app signals
   about its own session that banking trojans must disturb: whether its window is being obscured
   by an overlay (touch events flagged as obscured), which accessibility services are enabled,
   and whether it was installed from an untrusted source. A small SDK in the bank’s app could send
   these minimal signals to BlueWatch. This targets the exact techniques in §3 without reading
   other apps. **[planned — feasibility study, board #17; needs Android API and Play-policy review]**

**Bigger idea for later — shared defence across South African banks.** Banks share model
updates, not customer data (federated learning), so a trojan first seen at one bank raises
risk at all of them. **[planned — needs partners, legal review and a technical spike; not claimed]**

## 6. Progress (as of 23 Oct 2026, 21:00 SAST)

- Working end to end in Docker: analyst screen, keyed API, audit trail, SIEM events, NVD context,
  behaviour profile, grounded AI brief (local model). **58 automated tests pass.**
- Measured on 76,708 KronoDroid apps (held-out tests): precision 0.98 · recall 0.97 (random
  split) · recall 0.93 on unseen malware families · runtime-behaviour-only recall 0.89 ·
  **49% false alarms on newer apps** (known gap).
- Local AI brief: 4 of 6 demo samples accepted by the grounding check; the rest fall back to a
  labelled template.
- Board: Sprint 1 (video) has 11 items; pitch deck at 3 slides with Q&A backups.
- Not done: collector/SDK, fresh Android data and commercial data rights, pilot, interviews.

## 7. Value proposition

**For** bank SOC and fraud teams in South Africa **who** cannot see when a customer’s Android
phone is compromised by banking malware, **BlueWatch Mobile is** a behavioural detection and
evidence service **that** flags risky apps, explains why in plain language without inventing
facts, and feeds the bank’s existing SIEM and fraud workflows. **Unlike** signature-based mobile
antivirus or opaque risk scores, **BlueWatch** shows its evidence, publishes its error rates,
runs inside the bank, and keeps a human in charge of every decision.

| For | Gain | Evidence today |
|---|---|---|
| SOC analyst | Faster, explainable triage of device-related fraud | Working analyst screen + AI brief [built]; time saved per case [assumption — measure in pilot] |
| Fraud team | Device-compromise signal for step-up checks instead of blanket friction | API built; real-time use [planned] |
| Bank | Audit-ready decisions; data stays in-house; plugs into current SIEM | Audit trail, local AI, SIEM events [built] |
| Customer | Fewer losses from overlay/OTP-stealing apps | Depends on deployment and the on-app sensor [planned] |
| Business | Paid pilot then annual licence; MSSP resale | Prices R270k pilot / ~R600k per bank per year [assumption, from proposal] |

## 8. For the video and slide 1 (verified lines only)

- “Three out of four South African smartphones run Android.” (StatCounter)
- “Kaspersky detected over 162,000 new mobile banking trojan packages in the first quarter of 2026 alone.” (Securelist, 18 May 2026)
- Do **not** use SABRIC loss figures until the primary report is read.
- Youth employment angle: **[TEAM TO ADD — board #40]**.
