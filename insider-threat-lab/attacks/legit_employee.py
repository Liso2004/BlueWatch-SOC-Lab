#!/usr/bin/env python3
"""
Simulates normal employee behavior
- Occasional customer lookups
- Standard work hours activity
- Reasonable query volume
"""

import requests
import time
import random
from datetime import datetime

BASE_URL = "http://localhost:5000"

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

def normal_activity(session, duration_minutes=30):
    """Simulate normal work activity"""
    print(f"\n🕒 Starting normal activity for {duration_minutes} minutes...")
    
    start_time = time.time()
    query_count = 0
    
    while time.time() - start_time < duration_minutes * 60:
        # Random action every 2-5 minutes (normal pace)
        wait_time = random.randint(120, 300)
        
        action = random.choice(['view_customers', 'search', 'dashboard'])
        
        if action == 'view_customers':
            response = session.get(f"{BASE_URL}/api/customers")
            if response.status_code == 200:
                query_count += 1
                print(f"  📊 Viewed customer list (query #{query_count})")
        
        elif action == 'search':
            # Legitimate search terms
            search_terms = ['Smith', 'John', 'account', 'gmail', 'New York']
            term = random.choice(search_terms)
            response = session.get(f"{BASE_URL}/api/search?q={term}")
            if response.status_code == 200:
                results = response.json()
                query_count += 1
                print(f"  🔍 Searched for '{term}' - {len(results)} results (query #{query_count})")
        
        else:
            # Just viewing dashboard
            session.get(f"{BASE_URL}/dashboard")
            print(f"  👀 Viewing dashboard")
        
        time.sleep(wait_time)
    
    print(f"\n✅ Normal activity complete: {query_count} queries over {duration_minutes} minutes")
    print(f"   Average: {query_count / (duration_minutes / 60):.1f} queries/hour")

if __name__ == '__main__':
    # Simulate analyst doing normal work
    session = login('analyst', 'password123')
    
    if session:
        normal_activity(session, duration_minutes=15)  # Run for 15 minutes