Perfect! I’ve taken your report and applied **uniform, professional Markdown styling** so it looks like a polished SOC/IR template. This includes:

* Consistent heading levels
* Uniform tables with borders and spacing
* Checkbox styling for response actions
* Monospaced blocks for logs and scripts
* Clear separation between sections with horizontal rules

Here’s the fully polished version:

---

# 🛡 SECURITY INCIDENT REPORT

**Incident ID:** `IR-2025-001`
**Severity:** `CRITICAL`
**Status:** `CONTAINED`
**Analyst:** `[Your Name]`
**Date:** `January 25, 2025`
**Classification:** `CONFIDENTIAL`

---

## 1. EXECUTIVE SUMMARY

On **January 25, 2025, at 14:32 UTC**, SecureBank's monitoring systems detected anomalous database activity from employee account **`jdoe`**. Analysis revealed an insider threat attempting to exfiltrate customer Personally Identifiable Information (PII) via multiple attack vectors:

* High-volume database queries (50+ in 10 minutes)
* Systematic data extraction via search functionality
* DNS tunneling for covert data transmission

The attack was detected within **5 minutes** using behavioral analytics and SIEM correlation. The account was immediately disabled, preventing full data exfiltration.

**Business Impact:**

| Impact Area       | Details                      |
| ----------------- | ---------------------------- |
| Records Accessed  | ~2,400 customer records      |
| Data Exfiltration | None confirmed (DNS blocked) |
| Compliance Risk   | GDPR potential fine: €48,000 |

**Root Cause:**

* Overly permissive database access for "employee" role
* Lack of data exfiltration prevention controls
* No row-level security on PII tables

---

## 2. INCIDENT DETAILS

### 2.1 Timeline of Events

| **Time (UTC)** | **Event**           | **Details**                                                    |
| -------------- | ------------------- | -------------------------------------------------------------- |
| 14:25:00       | Initial Login       | User `jdoe` logged in from IP `10.0.2.15`                      |
| 14:26:00       | Baseline Activity   | Normal dashboard access, 2 customer queries                    |
| 14:30:00       | **Attack Begins**   | Query rate spike detected                                      |
| 14:30:15       | Database Queries    | 10 queries in 90 sec (baseline: 2/hour)                        |
| 14:31:30       | Search Exploitation | Wildcard searches (`"a"`, `"b"`, `"c"`) extracting all records |
| 14:32:00       | **Alert Triggered** | Wazuh rule `100002` fired                                      |
| 14:32:30       | DNS Exfiltration    | 127 DNS queries to suspicious domain                           |
| 14:33:00       | SOC Investigation   | Analyst confirmed malicious activity                           |
| 14:34:00       | **Containment**     | Account `jdoe` disabled                                        |
| 14:35:00       | Network Isolation   | IP `10.0.2.15` blocked at firewall                             |
| 14:40:00       | Forensics           | Forensic image captured                                        |
| 14:45:00       | Evidence Collection | Application, DB, network logs secured                          |

**Total Time to Detection:** 2 minutes
**Total Time to Containment:** 5 minutes

---

## 3. TECHNICAL ANALYSIS

### 3.1 Attack Vectors

#### 3.1.1 High-Volume Database Queries

**Method:** Rapid successive calls to `/api/customers`

**Evidence:**

```text
2025-01-25 14:30:15 - INFO - DATABASE_QUERY: SELECT customers | Rows: 50 - USER:jdoe
2025-01-25 14:30:18 - INFO - DATABASE_QUERY: SELECT customers | Rows: 50 - USER:jdoe
2025-01-25 14:30:21 - INFO - DATABASE_QUERY: SELECT customers | Rows: 50 - USER:jdoe
[... 47 more similar queries ...]
```

**Impact:** ~2,400 customer records accessed
**MITRE ATT&CK:** T1213 – Data from Information Repositories

#### 3.1.2 Search Functionality Abuse

**Method:** Single-character wildcard searches to extract all records

**Evidence:**

```text
2025-01-25 14:31:30 - INFO - SEARCH_QUERY: Search: "a" | Results: 243 - USER:jdoe
2025-01-25 14:31:45 - INFO - SEARCH_QUERY: Search: "b" | Results: 198 - USER:jdoe
2025-01-25 14:32:00 - INFO - SEARCH_QUERY: Search: "c" | Results: 215 - USER:jdoe
```

**Impact:** Systematic extraction of entire customer database
**MITRE ATT&CK:** T1078 – Valid Accounts

#### 3.1.3 DNS Tunneling Exfiltration

**Method:** Base64-encoded data via DNS queries

**Evidence:**

```text
DNS Query: aGVsbG8ud29ybGQ=.exfil.attacker-c2.com
DNS Query: YWNjb3VudDoxMjM0NTY=.exfil.attacker-c2.com
[Entropy: 4.8 - SUSPICIOUS]
```

**Impact:** Attempted covert exfiltration
**MITRE ATT&CK:** T1048.003 – Exfiltration Over Alternative Protocol (DNS)

---

### 3.2 Detection Methods

#### 3.2.1 Behavioral Analytics

**Baseline for `jdoe`:**

* Avg: 2.3 queries/hour
* Std Dev: 0.8
* Threshold: 4.7 queries/hour (mean + 3σ)

**Observed:** 52 queries in 10 min → **66x above baseline** 🚨

#### 3.2.2 SIEM Correlation (Wazuh)

```xml
<rule id="100002" level="12" frequency="10" timeframe="120">
  <description>Possible data exfiltration: 10+ queries in 2 minutes</description>
</rule>
```

* Severity: HIGH (12/15)
* Trigger: 10 queries in 120 sec
* Source: `jdoe@10.0.2.15`

#### 3.2.3 DNS Entropy Analysis

* Normal: 2.5–3.5
* Observed: 4.8
* Query length: 63 characters
* Pattern: consistent subdomain structure

---

## 4. INDICATORS OF COMPROMISE (IOCs)

| **Type**      | **Value**                      | **Context**                  |
| ------------- | ------------------------------ | ---------------------------- |
| Account       | `jdoe@securebank.local`        | Compromised employee account |
| IP Address    | `10.0.2.15`                    | Source of malicious activity |
| Domain        | `exfil.attacker-c2.com`        | DNS exfiltration destination |
| User-Agent    | `python-requests/2.31.0`       | Automated script signature   |
| Query Pattern | Single-char searches (a-z,0-9) | Data extraction method       |

---

## 5. RESPONSE ACTIONS

### 5.1 Immediate (Completed)

* [x] Account `jdoe` disabled at 14:34 UTC
* [x] Source IP `10.0.2.15` blocked at firewall
* [x] Active sessions terminated
* [x] Forensic evidence collected:

  * Application logs (`banking_app.log`)
  * Database query logs
  * Network packet captures
  * System memory dump

### 5.2 Short-Term (Within 72 hours)

* [ ] Audit all "employee" accounts for similar activity
* [ ] Review past 30-day access logs
* [ ] Interview employee `jdoe` (HR involvement)
* [ ] Legal notification (potential law enforcement)
* [ ] Implement Database Activity Monitoring (DAM)

### 5.3 Long-Term (Within 30 days)

* [ ] Deploy row-level security on PII tables
* [ ] Implement UEBA (User Entity Behavior Analytics)
* [ ] Deploy DNS firewall with entropy-based filtering
* [ ] Mandatory security awareness training for privileged users
* [ ] Quarterly insider threat tabletop exercises

---

## 6. LESSONS LEARNED

### 6.1 What Worked ✅

1. Behavioral Analytics detected anomaly within 2 minutes
2. Centralized Logging (ELK Stack) enabled rapid correlation
3. SIEM rules (Wazuh) provided actionable intelligence
4. Incident Response playbook allowed 5-minute containment

### 6.2 What Didn't Work ❌

1. No pre-alert for excessive SELECT queries
2. DNS monitoring not enabled before incident
3. Role permissions too permissive

### 6.3 Recommendations

1. Implement DLP for database exports
2. Deploy User Activity Monitoring (UAM) with real-time alerts
3. Enforce least privilege principle
4. Red Team exercise for HTTPS tunneling exfiltration

---

## 7. REGULATORY IMPACT

**GDPR Compliance:**

* Article 33: Breach notification within 72 hours
* Article 34: Direct notification if high risk

**Current Status:** Data access confirmed, exfiltration blocked

**Recommended Legal Actions:**

* Consult DPO
* Document breach in Article 30 processing records
* Prepare notification templates (pending DPO assessment)

---

## 8. ATTACHMENTS

* Full application logs (`banking_app.log`) – 2.4 MB
* Elasticsearch query results – JSON export
* Wazuh alert details – XML export
* Network packet capture (DNS queries) – PCAP file
* Forensic timeline visualization (Kibana screenshot)
* Anomaly detection script output

---

## 9. APPROVAL

**Prepared by:** `[Your Name]`, SOC Analyst
**Reviewed by:** `[SOC Lead Name]`
**Approved by:** `[CISO Name]`

**Distribution:**

* Security Operations Center (SOC)
* Chief Information Security Officer (CISO)
* Human Resources (HR)
* Legal Department
* Data Protection Officer (DPO)

**Report Classification:** `CONFIDENTIAL`
**Retention Period:** 7 years

**End of Report**