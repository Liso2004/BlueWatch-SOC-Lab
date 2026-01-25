# 🛡️ Insider Threat Detection Lab – Banking Application

A hands-on **SOC-style security monitoring lab** that simulates insider threats and authentication abuse in a banking environment. This project uses a vulnerable banking-style application integrated with the **ELK Stack (Elasticsearch, Logstash, Kibana)** and **Wazuh** to ingest, analyze, and visualize security-relevant logs.

---

## 🎯 Project Goals

- Simulate insider threat and authentication abuse scenarios
- Centralize application and security logs
- Visualize suspicious behavior using SOC-style dashboards
- Build detection-ready KPIs aligned with real SOC workflows

---

## 🧰 Tech Stack

### Application

- Node.js / Express (Banking App)
- MySQL 8.0 (Transactional Database)

### Security & Monitoring

- Elasticsearch 8.11
- Logstash 8.11
- Kibana 8.11
- Wazuh Manager 4.7

### Infrastructure

- Docker & Docker Compose

---

## 🏗️ Architecture Overview

```
[ Banking App ]
      │
      ├── App Logs ──▶ Logstash ──▶ Elasticsearch ──▶ Kibana Dashboards
      │
      └── System Events ──▶ Wazuh ──▶ Security Alerts
```

---

## 🚀 Getting Started

### 1️⃣ Prerequisites

- Docker
- Docker Compose
- Git

---

### 2️⃣ Clone the Repository

```
git clone <repository-url>
cd insider-threat-lab
```

---

### 3️⃣ Start the Lab

```
docker-compose up -d
```

Verify containers:

```
docker ps
```

---

## 🔍 Accessing the Services

| Service       | URL                                                |
| ------------- | -------------------------------------------------- |
| Banking App   | [http://localhost:5000](http://localhost:5000)     |
| Kibana        | [http://localhost:5601](http://localhost:5601)     |
| Elasticsearch | [http://localhost:9200](http://localhost:9200)     |
| Wazuh API     | [https://localhost:55000](https://localhost:55000) |

---

## 📊 Kibana Setup

### Create Index Pattern

- Navigate to **Stack Management → Index Patterns**
- Index pattern: `banking-logs-*`
- Time field: `@timestamp`

---

## 📈 SOC Dashboard Panels

### KPI Strip

- 🚨 Failed Logins
- ✅ Successful Logins
- 👤 Active Users
- 🌙 After-Hours Activity

### Behavioral Analysis

- Login Activity Timeline
- Query Volume Over Time
- Top Querying Users
- Failed Logins by User

### Source & Risk Indicators

- Top Source IPs
- Unique IPs per User
- Sensitive Data Access
- High-Risk Database Operations

---

## 🧪 Detection Examples

- Multiple failed logins per user
- After-hours authentication attempts
- High-volume querying behavior
- Access to sensitive customer data
- Unusual IP diversity per account

---

## 🧠 SOC Concepts Demonstrated

- Log ingestion pipelines
- Time-based behavioral analysis
- Insider threat detection patterns
- KPI-driven security monitoring
- ELK-based SOC dashboards

---

## 📌 Future Enhancements

- Alerting rules in Kibana
- MITRE ATT&CK mapping
- Wazuh → ELK correlation
- GeoIP enrichment
- Role-based detection dashboards

---

## 👤 Author

**Liso Hlatshwayo**
Full-Stack Developer | Cybersecurity Enthusiast
Google Cybersecurity Professional Certificate

---

## ⚠️ Disclaimer

This project is for **educational and lab purposes only**. Do not deploy in production environments.
