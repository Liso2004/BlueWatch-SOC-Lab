"""
API keys for system-to-system calls to /api/v1/mobile/*.

Configuration holds only SHA-256 hashes of keys, never the keys themselves:

    BLUEWATCH_API_KEYS="soc-siem:<sha256 hex>,fraud-engine:<sha256 hex>"

Create a key for a client (prints the key once, and the line to add to .env):

    python -m mobile_risk.apikeys new soc-siem
"""

import hashlib
import hmac
import os
import re
import secrets
import sys

CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def configured_clients():
    clients = {}
    for entry in filter(None, (e.strip() for e in os.getenv("BLUEWATCH_API_KEYS", "").split(","))):
        name, _, digest = entry.partition(":")
        if CLIENT_RE.match(name) and re.fullmatch(r"[0-9a-f]{64}", digest):
            clients[name] = digest
    return clients


def client_for(key):
    """Return the client name for a presented key, or None. Constant-time per comparison."""
    if not key or len(key) > 200:
        return None
    digest = hash_key(key)
    match = None
    for name, expected in configured_clients().items():
        if hmac.compare_digest(digest, expected):
            match = name
    return match


def new_key(client):
    if not CLIENT_RE.match(client):
        raise ValueError("client name: lowercase letters, digits and '-', 2-41 characters")
    key = "bwm_" + secrets.token_urlsafe(32)
    return key, f"{client}:{hash_key(key)}"


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "new":
        sys.exit("usage: python -m mobile_risk.apikeys new <client-name>")
    key, entry = new_key(sys.argv[2])
    print(f"API key for {sys.argv[2]} (shown once, give it to that client only):\n  {key}\n")
    print(f"Add to BLUEWATCH_API_KEYS in .env (comma-separate multiple clients):\n  {entry}")
