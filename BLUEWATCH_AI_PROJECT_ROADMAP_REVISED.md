# BlueWatch AI — Revised Project Roadmap

Repository: `Liso2004/BlueWatch-SOC-Lab`
Branch reviewed: `bulk`

## Confirmed Runtime

BlueWatch is already Docker-based. Current Compose services are:

- `banking-app` — Python/Flask
- `mysql` — MySQL 8.0 container
- `elasticsearch`
- `kibana`
- `logstash`
- `wazuh`

The Flask app connects to MySQL over the Docker network using the hostname `mysql`.

**No host MySQL installation is required.**

Your existing local Python virtual environment can stay. The `bulk` branch does not contain a tracked `venv/` or `.venv/`, which is good; add those paths to `.gitignore` so the local venv stays untracked.

## Confirmed Issues to Fix

1. Hard-coded DB credentials exist in Docker Compose and `banking_app.py`.
2. No tracked `.gitignore` exists in the reviewed branch.
3. Dockerfile creates `/var/logs/app`, but Flask/Compose use `/var/log/app`.
4. `SEARCH_QUERY` logs `Results: N`, while the anomaly parser only extracts `Rows: N`.
5. `README.md` incorrectly says Node.js/Express; the app is Flask/Python.
6. The docs describe Zeek, but there is no Zeek service in current Compose.
7. MySQL schema is already mounted into `/docker-entrypoint-initdb.d/init_db.sql`, so a fresh MySQL volume initializes automatically; manual import should be troubleshooting/reset only.
8. The setup guide says MySQL is exposed on host port 3306, but current Compose does not publish that port.
9. README references tests/files not present in the reviewed branch.
10. Both `README.md` and `README.MD` exist.
11. A Wazuh private-key file is tracked. If it is active/generated, replace it and move runtime key handling out of source control.

## Revised Architecture

```text
Host
|
|-- existing local Python venv
|   `-- optional host-run attack/dev scripts
|
`-- Docker Compose
    |-- banking-app
    |-- mysql
    |-- elasticsearch
    |-- logstash
    |-- kibana
    |-- wazuh
    |-- bluewatch-ai        # new later
    `-- bluewatch-dashboard # new later
```

Do not install another MySQL server locally.
Do not replace Docker with the venv.

## Configuration Strategy

Add a root `.env` only as Docker Compose configuration. Docker Compose reads it automatically for `${VARIABLE}` interpolation.

`.env.example`:

```env
MYSQL_ROOT_PASSWORD=
MYSQL_DATABASE=banking
MYSQL_USER=bankapp
MYSQL_PASSWORD=

DB_HOST=mysql
DB_NAME=banking
DB_USER=bankapp
DB_PASSWORD=

AI_PROVIDER=
AI_API_KEY=
AI_MODEL=
```

Keep the real `.env` local and untracked.

## Immediate Project Board

| ID | Task | Priority |
|---|---|---:|
| BWAI-001 | Add `.gitignore` for venv, `.env`, logs, generated secrets | Critical |
| BWAI-002 | Add `.env.example` for Compose configuration | Critical |
| BWAI-003 | Replace hard-coded DB credentials with Compose variables | Critical |
| BWAI-004 | Read DB config from environment in Flask | Critical |
| BWAI-005 | Fix Dockerfile log directory | High |
| BWAI-006 | Fix `Rows:` / `Results:` parser mismatch | High |
| BWAI-007 | Add parser tests | High |
| BWAI-008 | Correct README stack/runtime claims | High |
| BWAI-009 | Correct Docker/MySQL setup docs | High |
| BWAI-010 | Mark Zeek as future scope or actually add it | Medium |
| BWAI-011 | Consolidate duplicate README files | Medium |
| BWAI-012 | Review tracked Wazuh private key | Critical |
| BWAI-013 | Define normalized `SecurityEvent` model | Critical |
| BWAI-014 | Build log/anomaly/Wazuh normalizers | High |
| BWAI-015 | Add deterministic MITRE mapping | High |
| BWAI-016 | Create FastAPI AI service | Critical |
| BWAI-017 | Add redaction + grounding validation | Critical |
| BWAI-018 | Add AI service to Docker Compose | High |
| BWAI-019 | Build React/TypeScript SOC dashboard | Medium |
| BWAI-020 | Create labelled evaluation scenarios | High |
| BWAI-021 | Measure accuracy/latency/hallucinations | High |
| BWAI-022 | Add CI and final portfolio docs | Medium |

## Step-by-Step

### 1. Keep the existing venv

Do not create a second venv if yours already works.

Add:

```gitignore
venv/
.venv/
__pycache__/
*.pyc
```

### 2. Add `.gitignore`

```gitignore
venv/
.venv/
__pycache__/
*.pyc

.env
.env.*
!.env.example

*.log

node_modules/
dist/

*.key
*.pem
```

Review Wazuh requirements before removing generated certificate files.

### 3. Add `.env.example`

Use the example above. This is only configuration for Docker Compose and future AI credentials.

### 4. Keep MySQL in Docker and parameterize it

```yaml
mysql:
  image: mysql:8.0
  environment:
    MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
    MYSQL_DATABASE: ${MYSQL_DATABASE}
    MYSQL_USER: ${MYSQL_USER}
    MYSQL_PASSWORD: ${MYSQL_PASSWORD}
```

Banking app:

```yaml
environment:
  DB_HOST: ${DB_HOST:-mysql}
  DB_USER: ${DB_USER}
  DB_PASSWORD: ${DB_PASSWORD}
  DB_NAME: ${DB_NAME:-banking}
```

### 5. Update Flask DB connection

```python
import os

def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "mysql"),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.getenv("DB_NAME", "banking"),
        cursorclass=pymysql.cursors.DictCursor,
    )
```

### 6. Fix Dockerfile log path

Change:

```dockerfile
RUN mkdir -p /var/logs/app
```

to:

```dockerfile
RUN mkdir -p /var/log/app
```

### 7. Keep automatic DB initialization

Because Compose mounts:

```text
./insider-threat-lab/app/init_db.sql
-> /docker-entrypoint-initdb.d/init_db.sql
```

a fresh MySQL volume initializes automatically.

Normal start:

```bash
docker compose up -d
```

Manual SQL import is only needed for reset/troubleshooting.

### 8. Fix anomaly parsing

Support both:

```text
Rows: 50
Results: 50
```

Example:

```python
count_match = re.search(r'(?:Rows|Results):\s*(\d+)', line)
```

Normalize to `rows_accessed`.

### 9. Add tests

Test:

- database query
- search query
- malformed line
- missing count
- normal baseline
- high query rate

### 10. Correct docs

Canonical README should say:

- Flask/Python banking app
- MySQL runs inside Docker
- no host MySQL required
- ELK + Wazuh are currently implemented
- Zeek is planned unless added
- DB initializes through Docker entrypoint
- MySQL is internal to Compose network
- local venv is optional for host-run scripts

### 11. Add normalized event schema

Create:

```text
bluewatch-ai/app/models/event.py
```

Use Pydantic with:

```text
event_id
timestamp
source
event_type
severity
user
source_ip
observed
baseline
evidence
mitre_candidates
```

### 12. Add normalizers

Create adapters for:

- Flask/application logs
- behavioral anomaly output
- Wazuh alerts

All return the same `SecurityEvent`.

### 13. Add deterministic MITRE enrichment

Example:

```python
MITRE_MAP = {
    "LOGIN_ABUSE": ["T1078"],
    "DATABASE_BULK_ACCESS": ["T1213"],
    "DNS_EXFILTRATION": ["T1048.003"],
}
```

The LLM explains mappings; it does not invent them.

### 14. Create FastAPI service

Create a separate service:

```text
bluewatch-ai/
  Dockerfile
  requirements.txt
  app/
```

Start with:

```text
GET /health
POST /api/triage
```

Do not install FastAPI into the banking-app container.

### 15. Add AI safety pipeline

```text
SecurityEvent
    -> Evidence Builder
    -> Redaction
    -> LLM
    -> Pydantic TriageResult
    -> Grounding Validator
```

Validate usernames, IPs, timestamps, numbers and ATT&CK IDs against source evidence.

### 16. Preserve non-AI detection

If the AI provider is unavailable, Wazuh/anomaly detection must still function normally.

### 17. Add AI service to Docker Compose

Only after it works independently.

### 18. Build dashboard later

Use React + TypeScript + Vite + Tailwind.

Start with:

```text
/incidents
/incidents/:id
/metrics
```

### 19. Evaluate with labelled scenarios

Use real lab scenarios:

- normal employee
- slow extraction
- aggressive extraction
- authentication abuse
- DNS only once its detection path is genuinely implemented

Measure:

- classification accuracy
- severity accuracy
- schema-valid rate
- unsupported evidence/hallucinations
- latency
- model cost

### 20. Final portfolio pass

Add CI, architecture docs, screenshots, demo incidents and only measured CV metrics.

## First Milestone

```text
[ ] Keep existing Docker architecture
[ ] Keep existing local venv
[ ] Add venv to .gitignore
[ ] Add root .env.example
[ ] Remove hard-coded DB credentials
[ ] Keep MySQL as Docker service
[ ] Fix Dockerfile log path
[ ] Fix Results/Rows parser mismatch
[ ] Add parser tests
[ ] Correct Flask/MySQL/Docker README claims
[ ] Decide Zeek scope
[ ] Review tracked Wazuh private key
```

Only after this milestone should the AI service be added.
