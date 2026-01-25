# Architecture Documentation

## System Overview

```
                    ┌─────────────────────────────────────┐
                    │      USER INTERACTION LAYER         │
                    │  ┌────────────────────────────────┐ │
                    │  │  Web Browser (localhost:5000)  │ │
                    │  └────────────────────────────────┘ │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │     APPLICATION LAYER               │
                    │  ┌────────────────────────────────┐ │
                    │  │  Flask Banking App             │ │
                    │  │  - Auth (bcrypt)               │ │
                    │  │  - Customer API                │ │
                    │  │  - Search API                  │ │
                    │  │  - Logging (structured)        │ │
                    │  └────────────────────────────────┘ │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │      DATA LAYER                     │
                    │  ┌────────────────────────────────┐ │
                    │  │  MySQL Database                │ │
                    │  │  - users table (credentials)   │ │
                    │  │  - customers table (PII)       │ │
                    │  │  - 2,400 sample records        │ │
                    │  └────────────────────────────────┘ │
                    └─────────────┬───────────────────────┘
                                  │
                                  │ Logs flow
                                  ▼
        ┌───────────────────────────────────────────────────┐
        │           LOGGING INFRASTRUCTURE                   │
        │                                                    │
        │  ┌──────────────┐  ┌──────────────┐             │
        │  │  App Logs    │  │  DB Logs     │             │
        │  │  (JSON)      │  │  (slow query)│             │
        │  └──────┬───────┘  └──────┬───────┘             │
        │         │                  │                      │
        │         └──────────┬───────┘                      │
        │                    ▼                              │
        │         ┌──────────────────────┐                 │
        │         │     Logstash         │                 │
        │         │  - Parse logs        │                 │
        │         │  - Extract fields    │                 │
        │         │  - Enrich data       │                 │
        │         └──────────┬───────────┘                 │
        │                    │                              │
        │                    ▼                              │
        │         ┌──────────────────────┐                 │
        │         │   Elasticsearch      │                 │
        │         │  - Index logs        │                 │
        │         │  - Search/aggregate  │                 │
        │         └──────────┬───────────┘                 │
        │                    │                              │
        │                    ▼                              │
        │         ┌──────────────────────┐                 │
        │         │      Kibana          │                 │
        │         │  - Visualizations    │                 │
        │         │  - Dashboards        │                 │
        │         │  - Timeline          │                 │
        │         └──────────────────────┘                 │
        └───────────────────────────────────────────────────┘
                                  │
                                  │ Alerts
                                  ▼
        ┌───────────────────────────────────────────────────┐
        │         DETECTION & ALERTING                       │
        │                                                    │
        │  ┌──────────────────────────────────────────┐    │
        │  │           Wazuh SIEM                      │    │
        │  │  - Correlation rules                     │    │
        │  │  - Frequency analysis                    │    │
        │  │  - Alert generation                      │    │
        │  └──────────────────────────────────────────┘    │
        │                                                    │
        │  ┌──────────────────────────────────────────┐    │
        │  │     Python Anomaly Detector              │    │
        │  │  - Baseline calculation                  │    │
        │  │  - Statistical analysis                  │    │
        │  │  - Threshold detection                   │    │
        │  └──────────────────────────────────────────┘    │
        │                                                    │
        │  ┌──────────────────────────────────────────┐    │
        │  │          Zeek (Network)                  │    │
        │  │  - DNS monitoring                        │    │
        │  │  - Entropy analysis                      │    │
        │  │  - Protocol extraction                   │    │
        │  └──────────────────────────────────────────┘    │
        └───────────────────────────────────────────────────┘
```

## Data Flow

1. **User Action** → Flask app receives HTTP request
2. **Application Processing** → App queries database, logs activity
3. **Logging** → Structured logs written to `/var/log/app/`
4. **Ingestion** → Logstash reads logs, parses fields
5. **Storage** → Elasticsearch indexes parsed logs
6. **Visualization** → Kibana displays real-time dashboards
7. **Detection** → Wazuh/Python scripts analyze patterns
8. **Alerting** → Anomalies trigger alerts for SOC review

## Network Architecture

```
┌──────────────────────────────────────────────────────┐
│          Docker Network: bank-network                │
│                                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ banking-app │  │ banking-db  │  │elasticsearch│ │
│  │ :5000       │  │ :3306       │  │ :9200       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │                │                  │        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   kibana    │  │  logstash   │  │    wazuh    │ │
│  │ :5601       │  │ :5044       │  │ :1514       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                                                       │
└──────────────────────────────────────────────────────┘
           │ Port mapping to host
           ▼
    Host Machine (localhost)
```

## Security Layers

### Layer 1: Application Security

- ✅ Bcrypt password hashing
- ✅ Session management
- ❌ **Intentionally vulnerable:** No rate limiting
- ❌ **Intentionally vulnerable:** Excessive DB permissions

### Layer 2: Detection

- ✅ Behavioral analytics
- ✅ SIEM correlation
- ✅ Network monitoring

### Layer 3: Response

- ✅ Automated alerting
- ✅ Forensic logging
- ✅ Incident response playbooks
