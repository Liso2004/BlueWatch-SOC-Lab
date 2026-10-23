# BlueWatch Mobile — 3-minute video script and capture run sheet

Due **Saturday 24 Oct 2026, 07:00 SAST** on the hackathon platform (Pitch Instructions). Upload
early — do not wait until 06:45. Maximum 3:00; anything longer may be cut. Lead with the demo.
Format and file size: still to be confirmed by the platform team — check before exporting.

Recording owner: Stacey-Lee (board #9). Narrator: **[TEAM TO DECIDE]**.

## Before recording (10 minutes)

1. `docker compose up -d` and wait until http://localhost:5601 (Kibana) loads.
2. NVD cache warm for Android 13 (already cached; check `insider-threat-lab/nvd_cache/android-13.0.json` exists).
3. AI case brief uses **Claude** (`AI_PROVIDER=anthropic`). Add the key to `.env` as
   `AI_API_KEY=...`, run `docker compose up -d banking-app`, and click the brief once on
   kd-73c16aa41738 to check it shows "Written by Claude". Without a key it shows the labelled
   template — say so honestly. (The free local model was tried but needs more RAM than this
   laptop has alongside the SIEM stack.)
4. Browser zoom 125%, close other tabs, notifications off, quiet room.
5. Log in once as `analyst` / `password123` so the session is ready.
6. Record screen + voice (Windows: Win+G Game Bar, or OBS / Teams / Zoom recording).

## Script (every number below is from `metrics.json` or the live screen)

### 0:00–0:30 · The problem (show deck slide 1)
> “We chose Challenge 3: Android banking malware. Three out of four smartphones in South Africa
> run Android. Kaspersky detected over 162,000 new mobile banking trojan packages in the first
> quarter of 2026 alone. These trojans abuse Android features — fake screens drawn over the banking
> app, accessibility access that reads the screen, and apps installed from links that skip store
> checks. New variants change faster than signature lists, so bank security teams need to see
> what an app *does*. That’s BlueWatch Mobile.”

### 0:30–1:45 · What we built — live demo (screen recording)
| Time | Do on screen | Say |
|---|---|---|
| 0:30 | Dashboard → **BlueWatch Mobile — Android App Risk** | “This is the analyst screen a bank’s security team uses.” |
| 0:38 | Click malware sample **kd-73c16aa41738** (SLocker ransomware, score 0.9975) | “These are real apps from the KronoDroid research dataset that the model never saw in training.” |
| 0:45 | Point at **FLAG FOR REVIEW**, score bar, “model agrees” | “Flagged for review — a risk score with the threshold, and the dataset label so you can check us.” |
| 0:55 | Scroll to **Behaviour profile** | “Evidence grouped by banking-malware technique: overlay, accessibility, SMS interception, dynamic code, network. Declared permissions are kept separate from what the app actually did at runtime.” |
| 1:08 | Click **Write AI case brief** | “Generative AI writes a plain-English brief for the analyst. Our grounding check rejects any number that isn’t in the evidence, so it can’t invent facts.” |
| 1:20 | Click **Confirmed malicious**; scroll to activity panel | “The analyst decides. Every decision is audited and becomes a label for the next model.” |
| 1:28 | Click a benign sample (e.g. **kd-6ddc7afd3baf**) → NOT FLAGGED | “A clean app is not flagged.” |
| 1:33 | NVD panel → Android 13.0 → **Look up in NVD** | “Separately, known vulnerabilities for the phone’s Android version from NIST — context, never part of the score.” |
| 1:40 | Kibana Discover, search `MOBILE_RISK_ASSESSMENT` | “And every result lands in the SIEM the bank already runs.” |

### 1:45–2:30 · Value proposition and AI (deck slide 2, then slide 3)
> “Bank SOC and fraud teams get Android app risk inside the tools they already use — an API with
> a key per bank system, events in their SIEM, and it runs inside the bank’s network. The AI:
> a machine-learning model on 475 behavioural and permission signals. On held-out apps, 98% of
> what it flags is truly malware, and it catches 93% of malware from families it has never seen.
> Using runtime behaviour alone it still catches 89% — so this is genuinely behavioural, not a
> signature list. Generative AI turns the evidence into a brief the analyst can act on.”
> **[TEAM TO ADD: one sentence on youth employment / socio-economic impact — board #40]**

### 2:30–3:00 · Responsible AI and next steps (deck slide 3 or the “What’s real” backup)
> “Our data is KronoDroid, a public research dataset — we cite it, and we need the author’s
> permission before commercial use. Who could be harmed? Customers wrongly flagged: on apps newer
> than its training data, the model falsely flags 49% of clean apps. That’s why it never blocks
> anyone — a human always decides — and why our first next step is fresh Android data. Then:
> 15 interviews with bank and fintech security teams, and a design-partner pilot.”

## Fallbacks
- If Docker or Kibana fails mid-recording: keep going, show the deck’s backup slide
  “How it works today”, and say which part was not shown live.
- If the AI brief shows the template: say “with no AI model connected it falls back to a
  template” — that is part of the safety design.

## Checklist before upload
- [ ] Duration ≤ 3:00
- [ ] Only lab credentials and research data on screen; no `.env`, keys or personal data
- [ ] Every number matches this script
- [ ] Upload finished and confirmation screenshot saved (board #9)
