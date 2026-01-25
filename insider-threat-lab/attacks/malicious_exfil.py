#!/usr/bin/env python3
"""
Simulates insider threat - data exfiltration
- High query volume
- Systematic data extraction
- Attempts to avoid detection with rate limiting
"""

import requests
import time
import json
import os
from datetime import datetime

BASE_URL = "http://localhost:5000"
EXFIL_DIR = "/tmp/exfiltrated_data"

def login(username, password):
    """Login and get session"""
    session = requests.Session()
    response = session.post(f"{BASE_URL}/login", data={
        'username': username,
        'password': password
    })
    
    if response.status_code == 200:
        print(f"✅ Logged in as {username}")
        return session
    else:
        print(f"❌ Login failed for {username}")
        return None

def exfiltrate_slow(session):
    """
    Slow exfiltration - trying to stay under radar
    But still anomalous compared to baseline
    """
    print(f"\n🔴 Starting data exfiltration (slow method)...")
    
    os.makedirs(EXFIL_DIR, exist_ok=True)
    
    all_customers = []
    query_count = 0
    
    # Use search with single characters to extract all data
    search_chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    
    for char in search_chars:
        response = session.get(f"{BASE_URL}/api/search?q={char}")
        
        if response.status_code == 200:
            results = response.json()
            all_customers.extend(results)
            query_count += 1
            print(f"  📥 Extracted {len(results)} records using search '{char}' (total: {len(all_customers)})")
            
            # Small delay to appear "normal" (but still too fast)
            time.sleep(random.randint(15, 30))
        else:
            print(f"  ❌ Query failed")
    
    # Save exfiltrated data
    output_file = f"{EXFIL_DIR}/customers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(all_customers, f, indent=2)
    
    print(f"\n🔴 Exfiltration complete!")
    print(f"   Total queries: {query_count}")
    print(f"   Records stolen: {len(all_customers)}")
    print(f"   Saved to: {output_file}")
    print(f"   ⚠️ This should trigger HIGH QUERY RATE alerts!")

def exfiltrate_aggressive(session):
    """
    Aggressive exfiltration - obvious to detection
    Rapid-fire queries
    """
    print(f"\n🔴 Starting aggressive exfiltration...")
    
    os.makedirs(EXFIL_DIR, exist_ok=True)
    
    all_customers = []
    query_count = 0
    start_time = time.time()
    
    # Rapid queries with minimal delay
    for i in range(50):
        response = session.get(f"{BASE_URL}/api/customers")
        
        if response.status_code == 200:
            results = response.json()
            all_customers.extend(results)
            query_count += 1
            print(f"  📥 Query #{query_count} - extracted {len(results)} records")
            
            # Very short delay (THIS WILL BE DETECTED)
            time.sleep(random.uniform(1, 3))
        else:
            break
    
    elapsed = time.time() - start_time
    
    # Save data
    output_file = f"{EXFIL_DIR}/aggressive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(all_customers, f, indent=2)
    
    print(f"\n🔴 Aggressive exfiltration complete!")
    print(f"   Queries: {query_count} in {elapsed:.1f} seconds")
    print(f"   Rate: {query_count / (elapsed / 60):.1f} queries/minute")
    print(f"   Saved to: {output_file}")
    print(f"   🚨 This DEFINITELY triggered alerts!")

if __name__ == '__main__':
    import sys
    import random
    
    # Malicious employee account
    session = login('jdoe', 'password123')
    
    if session:
        if len(sys.argv) > 1 and sys.argv[1] == 'aggressive':
            exfiltrate_aggressive(session)
        else:
            exfiltrate_slow(session)