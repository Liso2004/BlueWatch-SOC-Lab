# 🏦 Insider Threat Detection Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Required-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-green)](https://www.python.org/)

> **A production-grade SOC analyst portfolio project demonstrating insider threat detection using behavioral analytics, SIEM correlation, and incident response.**

Built to showcase real-world security monitoring capabilities for SOC Analyst, Threat Detection, and Security Engineering roles.

---

## 🎯 Project Overview

This lab simulates a banking environment where a malicious insider attempts to exfiltrate customer PII through multiple attack vectors. The project demonstrates:

- **Behavioral analytics** to establish baselines and detect anomalies
- **SIEM correlation** using Wazuh rules
- **Centralized logging** with ELK Stack
- **Network monitoring** for DNS exfiltration
- **Professional incident response** with complete documentation

### Key Achievement

✅ **Detected data exfiltration in under 5 minutes using behavioral analytics** — something traditional signature-based tools would have missed.

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────┐
│  ATTACK INFRASTRUCTURE                               │
│  ├─ Flask Banking App (vulnerable endpoints)        │
│  ├─ MySQL Database (2,400 customer records)         │
│  └─ Attack Scripts (legitimate vs malicious)        │
└─────────────────────────────────────────────────────┘
              ↓ All activity logged ↓
┌─────────────────────────────────────────────────────┐
│  DETECTION INFRASTRUCTURE                            │
│  ├─ ELK Stack (log aggregation & visualization)     │
│  ├─ Wazuh (SIEM with custom correlation rules)      │
│  ├─ Zeek (network traffic analysis)                 │
│  └─ Python (custom anomaly detection)               │
└─────────────────────────────────────────────────────┘
```

![Architecture Diagram](docs/architecture.png)

---

## 🎭 Attack Scenarios

### Scenario 1: Legitimate Baseline

- Normal employee behavior: 2-3 queries/hour
- Typical search patterns
- Standard dashboard usage

### Scenario 2: Slow Exfiltration

- Systematic data extraction using wildcard searches
- Rate-limited to appear "normal"
- **Detection:** Behavioral analytics flagged 66x deviation from baseline

### Scenario 3: DNS Tunneling

- Base64-encoded data in DNS subdomains
- Bypasses traditional DLP
- **Detection:** Shannon entropy analysis (4.8 vs normal 2.5-3.5)

### Scenario 4: Aggressive Extraction

- 50+ database queries in 10 minutes
- Obvious to any monitoring system
- **Detection:** SIEM correlation rule triggered in 2 minutes

---

## 🛡️ Detection Methods

### 1. Behavioral Analytics (Python)

```python
# Establishes baseline: mean + 3σ threshold
baseline = {
    'mean': 2.3 queries/hour,
    'stdev': 0.8,
    'threshold': 4.7 queries/hour
}

# Attack detected:
observed_rate = 312 queries/hour  # 66x above baseline
```

**Result:** Anomaly detected ✅

### 2. SIEM Correlation (Wazuh)

```xml
<rule id="100002" level="12" frequency="10" timeframe="120">
  <description>10+ queries in 2 minutes - possible exfiltration</description>
</rule>
```

**Result:** Alert fired at 14:32 UTC ✅

### 3. DNS Entropy Analysis (Zeek)

```
Normal DNS: "google.com" (entropy: 2.8)
Malicious: "aGVsbG8ud29ybGQ=.exfil.attacker-c2.com" (entropy: 4.8)
```

**Result:** High-entropy queries flagged ✅

---

## 📝 Professional Deliverables

### [Incident Report](reports/incident_report_IR-2025-001.md)

Complete SOC incident report including:

- Executive summary (non-technical)
- Technical analysis with MITRE ATT&CK mapping
- Timeline reconstruction (minute-by-minute)
- Indicators of Compromise (IOCs)
- Response actions and remediation roadmap
- Lessons learned

**Highlights:**

- Detection time: **2 minutes**
- Containment time: **5 minutes**
- Records accessed: 2,400 (exfiltration blocked)

### [Executive Summary](reports/executive_summary.md)

Business-focused summary for C-level stakeholders showing:

- $485K+ in prevented losses
- Quick response metrics
- Regulatory compliance considerations

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- 50GB disk space
- 8GB RAM minimum

### Installation

```bash
# Clone the repository
git clone https://github.com/[your-username]/insider-threat-detection-lab.git
cd insider-threat-detection-lab

# Start all services
docker-compose up -d

# Wait for services to initialize (2-3 minutes)
sleep 120

# Initialize database
docker exec -i banking-db mysql -ubankapp -pBankApp123! < app/init_db.sql

# Verify services
docker-compose ps
```

**Access Points:**

- Banking App: http://localhost:5000
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

### Running Attack Scenarios

```bash
# Scenario 1: Establish baseline (normal behavior)
python3 attacks/legit_employee.py

# Scenario 2: Slow exfiltration
python3 attacks/malicious_exfil.py

# Scenario 3: DNS tunneling
python3 attacks/dns_tunnel.py

# Scenario 4: Aggressive extraction
python3 attacks/malicious_exfil.py aggressive
```

### Analyzing Results

```bash
# Run anomaly detection
docker exec banking-app python3 detection/anomaly_detector.py

# Generate timeline
docker exec banking-app python3 analysis/timeline.py

# View Elasticsearch data
curl http://localhost:9200/banking-logs-*/_count

# Access Kibana dashboards
# Open http://localhost:5601 > Dashboard > "Security Monitoring Dashboard"
```

---

## 📁 Project Structure

```
insider-threat-detection-lab/
├── README.md
├── docker-compose.yml
├── app/
│   ├── banking_app.py           # Flask application with logging
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── templates/               # HTML templates
│   └── init_db.sql              # Database schema + sample data
├── attacks/
│   ├── legit_employee.py        # Baseline behavior script
│   ├── malicious_exfil.py       # Data exfiltration scenarios
│   └── dns_tunnel.py            # DNS tunneling attack
├── detection/
│   ├── anomaly_detector.py      # Behavioral analytics
│   ├── elk/
│   │   └── logstash.conf        # Log parsing configuration
│   └── wazuh/
│       └── local_rules.xml      # SIEM correlation rules
├── analysis/
│   ├── timeline.py              # Incident timeline generator
│   └── investigate.sh           # Elasticsearch queries
├── reports/
│   ├── incident_report_IR-2025-001.md
│   └── executive_summary.md
└── docs/
    ├── architecture.png
    ├── attack_flow.png
    ├── detection_timeline.png
    └── setup_guide.md
```

---

## 🎓 Skills Demonstrated

| **Category**             | **Skills**                                    | **Tools**           |
| ------------------------ | --------------------------------------------- | ------------------- |
| **Log Analysis**         | Parsing, correlation, timeline reconstruction | ELK Stack, Python   |
| **SIEM Operations**      | Rule creation, alert tuning, threat hunting   | Wazuh               |
| **Behavioral Analytics** | Baseline calculation, anomaly detection       | Python (statistics) |
| **Network Analysis**     | DNS monitoring, entropy analysis              | Zeek                |
| **Incident Response**    | Detection, containment, reporting             | SOC playbooks       |
| **Scripting**            | Automation, custom detections                 | Python              |
| **Documentation**        | Technical & executive reporting               | Markdown            |

---

## 🎯 Real-World Application

This project simulates actual SOC analyst responsibilities:

### ✅ **Threat Detection**

- Behavioral baselines to catch "low and slow" attacks
- Correlation of multiple data sources (app logs + network + database)
- Custom detection logic for organization-specific threats

### ✅ **Incident Response**

- Alert triage (distinguishing true positives from false positives)
- Forensic timeline reconstruction
- Evidence collection and preservation

### ✅ **Communication**

- Technical incident reports for SOC teams
- Executive summaries for business stakeholders
- Remediation recommendations for engineering teams

---

## 📈 Detection Results

### Attack Detection Metrics

| **Metric**      | **Baseline (analyst)** | **Attack (jdoe)** | **Detection**      |
| --------------- | ---------------------- | ----------------- | ------------------ |
| Query Rate      | 2.3/hour               | 312/hour          | ✅ 66x deviation   |
| Alert Time      | N/A                    | 2 minutes         | ✅ Sub-5min SLA    |
| Containment     | N/A                    | 5 minutes         | ✅ Rapid response  |
| False Positives | 0                      | 0                 | ✅ Clean detection |

### MITRE ATT&CK Coverage

- **T1078** - Valid Accounts (credential abuse)
- **T1213** - Data from Information Repositories (database access)
- **T1048.003** - Exfiltration Over Alternative Protocol (DNS)

---

## 🔧 Customization

### Add Custom Detection Rules

Edit `detection/wazuh/local_rules.xml`:

```xml
<rule id="100005" level="10">
  <match>YOUR_PATTERN</match>
  <description>Your custom detection logic</description>
</rule>
```

### Modify Attack Scenarios

Edit attack scripts to simulate different TTPs:

- SQL injection attempts
- Privilege escalation
- Lateral movement
- Credential dumping

### Adjust Thresholds

Tune behavioral analytics in `detection/anomaly_detector.py`:

```python
# Change detection sensitivity
threshold = baseline['mean'] + (2 * baseline['stdev'])  # Lower threshold
```

---

## 🧪 Testing & Validation

### Unit Tests

```bash
# Test application endpoints
python3 tests/test_app.py

# Test detection logic
python3 tests/test_anomaly_detection.py
```

### Validation Checklist

- ✅ All Docker services running
- ✅ Database populated with 2,400+ records
- ✅ Logs flowing to Elasticsearch
- ✅ Kibana dashboards displaying data
- ✅ Wazuh rules loaded correctly
- ✅ Attack scripts execute without errors
- ✅ Anomaly detector identifies malicious behavior

---

## 🎤 Interview Talking Points

### "Tell me about this project"

> _"I built an insider threat detection lab that simulates a banking environment where a malicious employee tries to steal customer data. The challenge was detecting someone with **legitimate access** — you can't just block them._
>
> _I used behavioral analytics to establish a baseline of normal activity, then created SIEM rules that correlated database queries with network traffic. When the 'attacker' started extracting data, my system detected it in **under 5 minutes** because their query rate was 66 times above baseline._
>
> _What I'm most proud of is the professional incident report. I wrote it the way real SOC analysts do — with timeline reconstruction, MITRE ATT&CK mapping, and both technical and executive summaries."_

### "What did you learn?"

> _"Three big lessons:_
>
> _First, **context beats signatures**. Traditional tools look for known bad patterns, but behavioral analytics caught an attack that looked 'legitimate' at the endpoint level._
>
> _Second, **centralized logging is non-negotiable**. I had application logs, database logs, and network logs all flowing into Elasticsearch. Without that correlation, I would have missed the DNS exfiltration attempt._
>
> _Third, **detection is only half the job**. The incident report took as long as building the lab. Hiring managers want analysts who can communicate findings to different audiences — technical teams, management, and legal."_

### "How does this relate to SOC work?"

> _"This is exactly what Tier 2 SOC analysts do:_
>
> _1. **Alert triage** — I tuned rules to minimize false positives_  
> _2. **Threat hunting** — I proactively searched for anomalies beyond alerts_  
> _3. **Incident response** — I followed detection → containment → eradication → recovery_  
> _4. **Documentation** — I produced evidence that could stand up in court_
>
> _The tools I used — ELK, Wazuh, Zeek — are open-source equivalents to enterprise SIEM platforms. The **methodology** is what matters, and I've practiced it end-to-end."_

---

## 🏆 Portfolio Impact

**Before this project:**

- Resume: "Familiar with SIEM concepts"
- Interview: "I've done some CTFs"

**After this project:**

- Resume: "Detected insider threat in <5 min using behavioral analytics"
- Interview: _[Shows incident report]_ "Here's the professional deliverable"

**Hiring manager reaction:** _"This person can do the job on day one."_

---

## 📚 Resources & References

### Learning Materials

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Incident Response Guide (SP 800-61)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS DFIR Posters](https://www.sans.org/posters/)

### Tool Documentation

- [ELK Stack Documentation](https://www.elastic.co/guide/index.html)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Zeek Documentation](https://docs.zeek.org/)

### Related Projects

- [Detection Lab](https://github.com/clong/DetectionLab) - AD threat detection
- [Mordor](https://github.com/OTRF/mordor) - Pre-recorded attack datasets

---

## 🤝 Contributing

Found a bug or want to add a detection scenario? Contributions welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit changes (`git commit -m 'Add SQL injection detection'`)
4. Push to branch (`git push origin feature/new-detection`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

---

## ⚠️ Disclaimer

**This is a deliberately vulnerable application for educational purposes.**

- ❌ DO NOT deploy to production environments
- ❌ DO NOT expose to public networks
- ❌ DO NOT use with real customer data
- ✅ Use only in isolated lab environments
- ✅ Intended for cybersecurity training and portfolio development

---

## 📬 Contact

**[Your Name]**  
🔗 LinkedIn: [Your LinkedIn]  
🐙 GitHub: [@your-username](https://github.com/your-username)  
📧 Email: your.email@example.com

---

## 🌟 Acknowledgments

Built as part of my transition from full-stack development to cybersecurity.

**Technologies:** Flask, MySQL, Docker, Elasticsearch, Kibana, Logstash, Wazuh, Zeek, Python

**Inspired by:** Real-world SOC operations, MITRE ATT&CK, and the need for production-ready portfolio projects.

---

<div align="center">

**If this helped you land a SOC role, give it a ⭐!**

</div>
