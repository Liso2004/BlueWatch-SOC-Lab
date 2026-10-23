"""
Behaviour profile: the app's signals grouped into the behaviour categories named in the
BlueWatch Mobile POC technical brief (accessibility, overlay, SMS/notification, dynamic code
loading, network, system calls).

Two kinds of signal, kept apart:
  declared  - a permission in the manifest (capability the app asks for; static)
  observed  - a runtime count from the dataset's dynamic analysis (system calls, contacted IPs);
              "elevated" when above the 90th percentile of benign training apps

A category the dataset cannot observe says so instead of being left out. Context for the
analyst only; it does not change the model score.
"""

CATEGORIES = [
    {
        "category": "Screen overlay",
        "why": "Fake screens drawn over the banking app to capture credentials",
        "declared": ["SYSTEM_ALERT_WINDOW"],
        "observed": [],
    },
    {
        "category": "Accessibility abuse",
        "why": "Reads the screen and acts for the user; also used for keylogging",
        "declared": ["BIND_ACCESSIBILITY_SERVICE"],
        "observed": [],
    },
    {
        "category": "SMS / notification interception",
        "why": "Steals one-time passwords from SMS or notifications",
        "declared": ["RECEIVE_SMS", "READ_SMS", "SEND_SMS", "BIND_NOTIFICATION_LISTENER_SERVICE"],
        "observed": [],
    },
    {
        "category": "Dynamic code / payload loading",
        "why": "Downloads or unpacks code after install to evade review",
        "declared": ["REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES"],
        "observed": ["execve", "mprotect", "mmap2", "clone"],
    },
    {
        "category": "Network behaviour",
        "why": "Contacts command-and-control servers or exfiltrates data",
        "declared": [],
        "observed": ["NrContactedIps", "connect", "sendto", "socket"],
    },
    {
        "category": "Persistence / device control",
        "why": "Survives reboots or resists removal",
        "declared": ["RECEIVE_BOOT_COMPLETED", "BIND_DEVICE_ADMIN"],
        "observed": [],
    },
    {
        "category": "Screen capture",
        "why": "Records the screen while banking",
        "declared": [],
        "observed": [],
        "not_available": "Not observable in this dataset (no screen-capture signal); planned for the "
                         "on-device collector study",
    },
]


def profile(x, index, benign_p90):
    out = []
    for c in CATEGORIES:
        signals = []
        for f in c["declared"]:
            if f in index:
                v = float(x[index[f]])
                signals.append({"feature": f, "kind": "declared permission", "value": v,
                                "flag": v > 0})
        for f in c["observed"]:
            if f in index:
                v = float(x[index[f]])
                p90 = float(benign_p90[index[f]])
                signals.append({"feature": f, "kind": "observed at runtime", "value": v,
                                "benign_p90": p90, "flag": v > p90})
        if c.get("not_available"):
            status = "not available"
        elif any(s["flag"] for s in signals):
            status = "present"
        else:
            status = "not seen"
        out.append({"category": c["category"], "why": c["why"], "status": status,
                    "signals": signals, "note": c.get("not_available")})
    return out
