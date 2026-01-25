# Complete Setup Guide

## System Requirements

### Minimum

- **OS:** Ubuntu 20.04+, macOS 11+, Windows 10 with WSL2
- **CPU:** 4 cores
- **RAM:** 8 GB
- **Disk:** 50 GB free space
- **Network:** Internet connection for Docker images

### Recommended

- **CPU:** 8 cores
- **RAM:** 16 GB
- **Disk:** 100 GB SSD

---

## Step-by-Step Installation

### 1. Install Docker

**Ubuntu/Debian:**

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**macOS:**
Download Docker Desktop from https://www.docker.com/products/docker-desktop

**Windows:**
Download Docker Desktop and enable WSL2 backend

### 2. Clone Repository

```bash
git clone https://github.com/[your-username]/insider-threat-detection-lab.git
cd insider-threat-detection-lab
```

### 3. Start Services

```bash
# Start all containers
docker-compose up -d

# Check status
docker-compose ps

# Expected output:
# banking-app       running  0.0.0.0:5000->5000/tcp
# banking-db        running  0.0.0.0:3306->3306/tcp
# elasticsearch     running  0.0.0.0:9200->9200/tcp
# kibana            running  0.0.0.0:5601->5601/tcp
# logstash          running  0.0.0.0:5044->5044/tcp
# wazuh-manager     running  0.0.0.0:1514->1514/tcp
```

### 4. Initialize Database

```bash
# Wait for MySQL to be ready
sleep 30

# Load schema and data
docker exec -i banking-db mysql -ubankapp -pBankApp123! < app/init_db.sql

# Verify data loaded
docker exec banking-db mysql -ubankapp -pBankApp123! -e "SELECT COUNT(*) FROM banking.customers;"
# Should show: 2400
```

### 5. Verify Services

```bash
# Test Flask app
curl http://localhost:5000
# Should return HTML

# Test Elasticsearch
curl http://localhost:9200
# Should return JSON with cluster info

# Test Kibana (in browser)
# Open http://localhost:5601
```

### 6. Configure Kibana

1. Open http://localhost:5601
2. Go to **Stack Management** > **Index Patterns**
3. Click **Create index pattern**
4. Enter pattern: `banking-logs-*`
5. Select `@timestamp` as time field
6. Click **Create**

---

## Troubleshooting

### Issue: Elasticsearch won't start

**Error:** `max virtual memory areas vm.max_map_count [65530] is too low`

**Fix:**

```bash
# Linux
sudo sysctl -w vm.max_map_count=262144

# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# macOS (Docker Desktop)
# Settings > Resources > Advanced > increase memory to 4GB+
```

### Issue: Port already in use

**Error:** `Bind for 0.0.0.0:5000 failed: port is already allocated`

**Fix:**

```bash
# Find what's using the port
sudo lsof -i :5000

# Kill the process or change port in docker-compose.yml
ports:
  - "5001:5000"  # Changed host port to 5001
```

### Issue: Logs not appearing in Kibana

**Check Logstash:**

```bash
docker-compose logs logstash

# Should see:
# "Successfully started Logstash API"
```

**Check log file exists:**

```bash
docker exec banking-app ls -la /var/log/app/
# Should show banking_app.log
```

**Manually trigger log:**

```bash
# Login to app to generate logs
curl -X POST http://localhost:5000/login \
  -d "username=jdoe&password=password123"
```

---

## Running the Lab

### Phase 1: Baseline (5-10 minutes)

```bash
python3 attacks/legit_employee.py
```

### Phase 2: Attack Scenarios (20 minutes)

```bash
# Slow exfiltration
python3 attacks/malicious_exfil.py

# DNS tunneling
python3 attacks/dns_tunnel.py

# Aggressive extraction
python3 attacks/malicious_exfil.py aggressive
```

### Phase 3: Analysis

```bash
# Run anomaly detector
docker exec banking-app python3 detection/anomaly_detector.py

# Generate timeline
docker exec banking-app python3 analysis/timeline.py

# View Kibana dashboards
# Open http://localhost:5601
```

---

## Cleanup

```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

---

## Next Steps

1. ✅ Review [incident report](../reports/incident_report_IR-2025-001.md)
2. ✅ Customize detection rules in `detection/wazuh/local_rules.xml`
3. ✅ Add your own attack scenarios
4. ✅ Tune anomaly detection thresholds
5. ✅ Create additional Kibana visualizations
