#!/usr/bin/env python3
"""
Behavioral anomaly detection for database queries
Establishes baseline and detects deviations
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

# Parse log file
def parse_logs(log_file):
    events = []
    with open(log_file, 'r') as f:
        for line in f:
            if 'DATABASE_QUERY' in line or 'SEARCH_QUERY' in line:
                # Extract timestamp, user, and rows
                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                user_match = re.search(r'USER:(\w+)', line)
                rows_match = re.search(r'Rows: (\d+)', line)
                
                if timestamp_match and user_match and rows_match:
                    events.append({
                        'timestamp': datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S'),
                        'user': user_match.group(1),
                        'rows': int(rows_match.group(1))
                    })
    return events

# Calculate baseline behavior
def calculate_baseline(events, user):
    user_events = [e for e in events if e['user'] == user]
    
    if len(user_events) < 10:
        return None
    
    # Calculate queries per hour
    queries_per_hour = defaultdict(int)
    for event in user_events:
        hour_bucket = event['timestamp'].replace(minute=0, second=0)
        queries_per_hour[hour_bucket] += 1
    
    rates = list(queries_per_hour.values())
    
    return {
        'mean': statistics.mean(rates),
        'stdev': statistics.stdev(rates) if len(rates) > 1 else 0,
        'max': max(rates),
        'total_queries': len(user_events)
    }

# Detect anomalies
def detect_anomalies(events, user, baseline):
    if not baseline:
        return []
    
    anomalies = []
    user_events = [e for e in events if e['user'] == user]
    
    # Check current hour rate
    current_hour = datetime.now().replace(minute=0, second=0)
    recent_events = [e for e in user_events if e['timestamp'] > current_hour - timedelta(hours=1)]
    current_rate = len(recent_events)
    
    # Anomaly: > 3 standard deviations from mean
    threshold = baseline['mean'] + (3 * baseline['stdev'])
    
    if current_rate > threshold:
        anomalies.append({
            'type': 'HIGH_QUERY_RATE',
            'user': user,
            'current_rate': current_rate,
            'baseline_mean': baseline['mean'],
            'threshold': threshold,
            'severity': 'HIGH' if current_rate > threshold * 1.5 else 'MEDIUM'
        })
    
    return anomalies

# Main execution
if __name__ == '__main__':
    log_file = "/var/log/app/banking_app.log"

    
    print("=== Behavioral Anomaly Detection ===\n")
    
    events = parse_logs(log_file)
    users = set(e['user'] for e in events)
    
    for user in users:
        baseline = calculate_baseline(events, user)
        if baseline:
            print(f"User: {user}")
            print(f"  Baseline: {baseline['mean']:.1f} queries/hour (σ={baseline['stdev']:.1f})")
            
            anomalies = detect_anomalies(events, user, baseline)
            if anomalies:
                for a in anomalies:
                    print(f"  🚨 ANOMALY: {a['type']} - {a['current_rate']} queries (threshold: {a['threshold']:.1f})")
            else:
                print(f"  ✅ No anomalies detected")
            print()