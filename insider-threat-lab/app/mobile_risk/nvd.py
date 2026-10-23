"""
Android platform vulnerability context from the NVD CVE API 2.0
(https://nvd.nist.gov/developers/vulnerabilities).

This answers "which published CVEs affect this Android OS version?" It is device/platform
exposure context and is kept separate from the malware verdict: a CVE does not make an app
malicious, and finding no CVE must not lower an app's malware risk.

Matching uses NVD's own CPE applicability data, not keyword search. A CVE is kept only if
one of its configurations marks `cpe:2.3:o:google:android` as *vulnerable* and the
requested version is covered:
  exact        - the CPE names this exact version
  range        - the version falls inside the CPE's versionStart/versionEnd bounds
  unspecified  - the CPE says "any version" with no bounds (weak; counted, not listed)
CVEs where Android is only the platform a vulnerable app runs on are dropped.

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ANDROID_CPE = "cpe:2.3:o:google:android:"
SUPPORTED_VERSIONS = ["10.0", "11.0", "12.0", "12.1", "13.0", "14.0", "15.0", "16.0"]
PAGE_SIZE = 500
CACHE_TTL_SECONDS = 24 * 3600
CACHE_DIR = Path(os.getenv("NVD_CACHE_DIR", Path(tempfile.gettempdir()) / "bluewatch-nvd"))
CONFIDENCE_ORDER = ["exact", "range", "unspecified"]

NOTICE = ("Platform vulnerability context from NVD. A CVE describes exposure of the Android "
          "OS version, not malicious behaviour by an app; no matching CVE does not lower malware "
          "risk. This product uses the NVD API but is not endorsed or certified by the NVD.")


class NVDError(RuntimeError):
    pass


def _version_tuple(v):
    return tuple(int(p) for p in v.split(".") if p.isdigit())


def _in_range(version, m):
    v = _version_tuple(version)
    if "versionStartIncluding" in m and v < _version_tuple(m["versionStartIncluding"]):
        return False
    if "versionStartExcluding" in m and v <= _version_tuple(m["versionStartExcluding"]):
        return False
    if "versionEndIncluding" in m and v > _version_tuple(m["versionEndIncluding"]):
        return False
    if "versionEndExcluding" in m and v >= _version_tuple(m["versionEndExcluding"]):
        return False
    return True


def match_confidence(cve, version):
    """Best confidence with which `cve` marks Android `version` as vulnerable, or None."""
    best = None
    bounds = ("versionStartIncluding", "versionStartExcluding",
              "versionEndIncluding", "versionEndExcluding")
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                if not m.get("vulnerable") or not crit.startswith(ANDROID_CPE):
                    continue
                cpe_version = crit.split(":")[5]
                if cpe_version == version:
                    found = "exact"
                elif cpe_version in ("*", "-") and any(b in m for b in bounds):
                    found = "range" if _in_range(version, m) else None
                elif cpe_version == "*":
                    found = "unspecified"
                else:
                    found = None
                if found and (best is None or
                              CONFIDENCE_ORDER.index(found) < CONFIDENCE_ORDER.index(best)):
                    best = found
    return best


def _cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key) or []
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0] if entries else None)
        if entry:
            data = entry["cvssData"]
            return {"version": data.get("version"), "base_score": data.get("baseScore"),
                    "severity": data.get("baseSeverity"), "vector": data.get("vectorString"),
                    "source": entry.get("source")}
    return None


def normalise(cve, confidence, retrieved_at):
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                       "No English description available.")
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return {
        "cve_id": cve["id"],
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss": _cvss(cve),
        "cwe": cwes,
        "match_confidence": confidence,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        "references": [r["url"] for r in cve.get("references", []) if r.get("url")][:3],
        "source": "NVD",
        "retrieved_at": retrieved_at,
    }


def _get(params, session=requests, retries=3):
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    for attempt in range(retries):
        try:
            r = session.get(NVD_API_URL, params=params, headers=headers, timeout=60)
        except requests.RequestException as e:
            err = f"network error: {e.__class__.__name__}"
        else:
            if r.status_code == 200:
                return r.json()
            err = f"HTTP {r.status_code}"
            if r.status_code not in (403, 429, 500, 502, 503, 504):
                break
        time.sleep(6 * (attempt + 1))
    raise NVDError(f"NVD request failed ({err})")


def fetch_android_cves(version, session=requests):
    """All NVD CVEs whose configurations involve `cpe:2.3:o:google:android:<version>`, paged."""
    # NVD asks unauthenticated clients to stay under 5 requests per 30 s.
    pause = 0.6 if os.getenv("NVD_API_KEY") else 6.0
    params = {"virtualMatchString": f"{ANDROID_CPE}{version}", "resultsPerPage": PAGE_SIZE,
              "startIndex": 0}
    cves = []
    while True:
        page = _get(params, session)
        cves.extend(v["cve"] for v in page.get("vulnerabilities", []))
        params["startIndex"] += PAGE_SIZE
        if params["startIndex"] >= page.get("totalResults", 0):
            return cves, page.get("totalResults", 0)
        time.sleep(pause)


def android_platform_context(version, limit=10, session=requests, now=time.time):
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"android_version must be one of {SUPPORTED_VERSIONS}")
    cache_file = CACHE_DIR / f"android-{version}.json"
    if cache_file.exists() and now() - cache_file.stat().st_mtime < CACHE_TTL_SECONDS:
        cached = json.loads(cache_file.read_text())
        cached["from_cache"] = True
    else:
        retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        raw, total = fetch_android_cves(version, session)
        matched = []
        for cve in raw:
            confidence = match_confidence(cve, version)
            if confidence:
                matched.append(normalise(cve, confidence, retrieved_at))
        cached = {"android_version": version, "cpe": f"{ANDROID_CPE}{version}",
                  "retrieved_at": retrieved_at, "nvd_candidates": total,
                  "matched": matched, "from_cache": False}
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(cached))

    matched = cached["matched"]
    counts = {c: sum(1 for m in matched if m["match_confidence"] == c) for c in CONFIDENCE_ORDER}
    severity = {}
    for m in matched:
        if m["match_confidence"] != "unspecified":
            s = (m["cvss"] or {}).get("severity") or "NONE"
            severity[s] = severity.get(s, 0) + 1
    listed = sorted((m for m in matched if m["match_confidence"] != "unspecified"),
                    key=lambda m: ((m["cvss"] or {}).get("base_score") or 0, m["published"] or ""),
                    reverse=True)
    return {
        "android_version": cached["android_version"],
        "cpe": cached["cpe"],
        "retrieved_at": cached["retrieved_at"],
        "from_cache": cached["from_cache"],
        "nvd_candidates": cached["nvd_candidates"],
        "match_counts": counts,
        "severity_counts_exact_or_range": severity,
        "top_cves": listed[:limit],
        "notice": NOTICE,
    }


if __name__ == "__main__":
    # Warm the cache before a demo:  python -m mobile_risk.nvd 13.0 14.0
    import sys
    for v in sys.argv[1:] or ["13.0"]:
        r = android_platform_context(v)
        print(v, r["match_counts"], "cached at", CACHE_DIR)
