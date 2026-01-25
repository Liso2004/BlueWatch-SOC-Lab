#!/usr/bin/env python3
"""
Generate incident timeline from logs
"""

import re
from datetime import datetime
from collections import defaultdict

def parse_timeline(log_file):
    events = []
    
    with open(log_file, 'r') as f:
        for line in f:
            # Extract key information
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            user_match = re.search(r'USER:(\w+)', line)
            ip_match = re.search(r'IP:([\d\.]+)', line)
            event_match = re.search(r'- (.*?) -', line)
            
            if timestamp_match and user_match and event_match:
                events.append({
                    'timestamp': timestamp_match.group(1),
                    'user': user_match.group(1),
                    'ip': ip_match.group(1) if ip_match else 'unknown',
                    'event': event_match.group(1)
                })
    
    return events

def generate_timeline_report(events, target_user='jdoe'):
    """Generate detailed timeline for incident report"""
    
    print(f"\n{'='*80}")
    print(f"INCIDENT TIMELINE - User: {target_user}")
    print(f"{'='*80}\n")
    
    user_events = [e for e in events if e['user'] == target_user]
    
    if not user_events:
        print("No events found for user")
        return
    
    # Group by minute for analysis
    events_by_minute = defaultdict(list)
    for event in user_events:
        dt = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
        minute_key = dt.strftime('%Y-%m-%d %H:%M')
        events_by_minute[minute_key].append(event)
    
    # Print timeline
    for minute in sorted(events_by_minute.keys()):
        events_in_minute = events_by_minute[minute]
        query_count = len([e for e in events_in_minute if 'QUERY' in e['event']])
        
        if query_count > 0:
            marker = "🚨" if query_count > 5 else "⚠️" if query_count > 2 else "📊"
            print(f"{marker} {minute} - {query_count} queries")
            
            # Show first few events
            for event in events_in_minute[:3]:
                print(f"     └─ {event['event'][:70]}")
            
            if len(events_in_minute) > 3:
                print(f"     └─ ... and {len(events_in_minute) - 3} more")
            print()
    
    # Summary statistics
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    
    total_queries = len([e for e in user_events if 'QUERY' in e['event']])
    logins = len([e for e in user_events if 'LOGIN' in e['event']])
    
    first_event = min(e['timestamp'] for e in user_events)
    last_event = max(e['timestamp'] for e in user_events)
    
    duration = datetime.strptime(last_event, '%Y-%m-%d %H:%M:%S') - \
               datetime.strptime(first_event, '%Y-%m-%d %H:%M:%S')
    
    print(f"First Activity: {first_event}")
    print(f"Last Activity:  {last_event}")
    print(f"Duration:       {duration}")
    print(f"Total Queries:  {total_queries}")
    print(f"Query Rate:     {total_queries / (duration.total_seconds() / 60):.1f} queries/minute")
    print(f"Logins:         {logins}")
    
    # Detection verdict
    print(f"\n{'='*80}")
    print("DETECTION VERDICT")
    print(f"{'='*80}")
    
    queries_per_minute = total_queries / (duration.total_seconds() / 60)
    
    if queries_per_minute > 10:
        print("🔴 CRITICAL: Extremely high query rate - likely data exfiltration")
    elif queries_per_minute > 5:
        print("🟠 HIGH: Suspicious query rate - requires investigation")
    elif queries_per_minute > 2:
        print("🟡 MEDIUM: Elevated query rate - monitor closely")
    else:
        print("🟢 LOW: Normal activity")

if __name__ == '__main__':
    log_file = '/var/log/app/banking_app.log'
    
    events = parse_timeline(log_file)
    
    # Analyze all users
    users = set(e['user'] for e in events)
    
    for user in users:
        generate_timeline_report(events, user)
        print("\n\n")