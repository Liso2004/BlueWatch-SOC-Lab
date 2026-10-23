# BlueWatch Mobile — live pitch Q&A crib sheet (2 minutes of judge questions)

Format (Master Operational Document §3.3): 5-minute pitch, max 3 slides, then **2 minutes of
Q&A**. Answer in ≤20 seconds, lead with the fact, then stop. Every number here is in
`insider-threat-lab/app/mobile_risk/artifacts/metrics.json` or a cited source. Backup slides
(hidden in the deck) are named for each answer — unhide only if asked to show.

Who answers: **[TEAM TO DECIDE]** — suggested: Liso for technical / business, Stacey-Lee for
product, demo and UX.

## 1. Model & technical quality (rubric 10%)

**“How accurate is it?”**
On 15,342 held-out apps it never saw, 98% of what it flags is truly malware and it catches 97%.
On malware families it has never seen, it still catches 93%. *(Backup: “How the model is trained”)*

**“What’s the catch?”**
Trained on older apps, it wrongly flags 49% of newer clean apps. We publish that, a human
always decides, and fresh Android data plus a newer-apps release test is our first fix.

**“Isn’t this just permissions — a signature list in disguise?”**
No. Trained on runtime behaviour alone — system calls and network, no permissions — it still
catches 89% of malware with 97% precision. Permissions add on top.

**“How do you know there’s no data leakage?”**
We removed antivirus results, family names and app hashes from the inputs, de-duplicated by
SHA-256, and our training script checks that no app appears in both training and test sets.
The unseen-families test also holds out whole malware families.

## 2. Data & methodology (10%)

**“Where is the data from — are you allowed to use it?”**
KronoDroid, a published research dataset of 76,708 real-device Android apps from 2008–2020. It’s
released for research with a citation, which we give. Commercial use needs the author’s
permission — that’s on our 30-day plan.

**“Can someone reproduce this?”**
Yes: two commands, fixed seed, about a minute; the deployed model reproduces byte-for-byte.
58 automated tests.

## 3. Application & experience (10%) · 8. UX & design (10%)

**“Who actually uses this, and how?”**
A bank SOC or fraud analyst: pick an app, see the verdict, the behaviour evidence and an AI
brief, then record a decision. Or the bank’s own systems call our API with their own key and
get the same answer in their SIEM.

**“What happens when the AI is wrong?”**
The analyst marks it a false positive. It’s audited and becomes a label for the next model —
the score never changes on its own, and nothing is ever blocked automatically.

## 4. Responsible AI (10%)

**“Who could be harmed?”**
Customers whose clean app is flagged — newer apps especially. So the score only prioritises
review; it never blocks accounts or devices, and we publish the error rate.

**“What about privacy?”**
We use app behaviour counts only — no messages, OTPs, credentials or personal data. It runs
inside the bank’s network, and the AI brief receives only the assessment facts, not who the
customer or analyst is. We don’t claim POPIA compliance — a real deployment needs a privacy
assessment.

**“Can the generative AI hallucinate?”**
It can try. Every brief is checked: any number, permission name or probability claim not in
the evidence, or anything contradicting the verdict, and it’s rejected and replaced with a
template. The analyst always sees which one they’re reading.

## 5. Innovation & generative AI (10%)

**“What’s new here?”**
Three things together: AI that is mechanically prevented from inventing facts; detection that
works on runtime behaviour, not signatures; and the whole stack runs inside the bank. Next, the
bank’s own app becomes the sensor — Android tells an app when an overlay covers it or which
accessibility services are on, exactly what trojans abuse.

**“Why not just use an LLM to detect malware?”**
LLMs aren’t reliable classifiers of behaviour counts and can’t be audited. The classifier
decides; the LLM only explains, and it’s fact-checked.

## 6. Problem-market fit & impact (10% — tie-break criterion)

**“Is this a real problem?”**
Three in four South African smartphones run Android (StatCounter, June 2026). Kaspersky detected
162,275 new mobile banking trojan packages in the first quarter of 2026 alone.

**“Who pays?”**
Bank and fintech security teams, and managed security providers who resell to them.

**“Youth employment / socio-economic impact?”**
**[TEAM TO ADD — board #40.]** Socio-economic: safer mobile banking for South Africa’s Android
users, who are most of the market.

## 7. Technical feasibility & prototype (10%)

**“Does it scale? Is it production-ready?”**
It’s a working prototype, not production. It runs in Docker with a keyed API, audit trail and SIEM
events; scoring is about 0.02 ms per app in batch. Production needs rate limiting, enterprise
login and a hardened deployment — on our board.

**“How do you get data from real phones?”**
Today the features come from a research dataset. Getting them from phones without root is our
biggest open question; our plan is an SDK in the bank’s own app, and we’ll prove feasibility
before building it.

## 9. Pitch, business case & commercial viability (20%)

**“How do you make money?”**
A paid six-month pilot, then an annual licence per bank — our planning figures are about R270k
and R600k a year, to be validated with buyers. Plus resale through managed security providers.

**“Who are your competitors?”**
Mobile threat defence and antivirus vendors. We don’t replace them — we add explainable,
auditable behaviour evidence that plugs into the bank’s own SIEM and fraud workflow.

**“What happens in the next six months?”**
Fifteen interviews with bank and fintech security teams, current Android data with commercial
rights, fix the newer-app false alarms, then one design-partner pilot.

**“Why iPhone later?”**
Android is 76% of the market and is where these attack techniques work; iOS restricts them.

## If you don’t know
“We haven’t measured that yet — here’s how we would.” Never estimate a number on stage.
