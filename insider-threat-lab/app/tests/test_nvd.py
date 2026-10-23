import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mobile_risk import nvd  # noqa: E402


def cpe(criteria, vulnerable=True, **bounds):
    return {"criteria": criteria, "vulnerable": vulnerable, **bounds}


def cve(cve_id, matches, score=None):
    c = {"id": cve_id, "published": "2024-01-01T00:00:00", "lastModified": "2024-02-01T00:00:00",
         "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
         "configurations": [{"nodes": [{"cpeMatch": matches}]}],
         "references": [{"url": f"https://example.org/{cve_id}"}]}
    if score is not None:
        c["metrics"] = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                           "cvssData": {"version": "3.1", "baseScore": score,
                                                        "baseSeverity": "HIGH"}}]}
    return c


EXACT = cve("CVE-A", [cpe("cpe:2.3:o:google:android:13.0:*:*:*:*:*:*:*")], 7.8)
RANGE_IN = cve("CVE-B", [cpe("cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                             versionStartIncluding="12.0", versionEndExcluding="14.0")], 9.8)
RANGE_OUT = cve("CVE-C", [cpe("cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                              versionEndExcluding="13.0")], 5.0)
ANY = cve("CVE-D", [cpe("cpe:2.3:o:google:android:*:*:*:*:*:*:*:*")])
PLATFORM_ONLY = cve("CVE-E", [cpe("cpe:2.3:a:someapp:someapp:1.0:*:*:*:*:android:*:*"),
                              cpe("cpe:2.3:o:google:android:-:*:*:*:*:*:*:*", vulnerable=False)])
OTHER_VERSION = cve("CVE-F", [cpe("cpe:2.3:o:google:android:12.0:*:*:*:*:*:*:*")])


@pytest.mark.parametrize("item,expected", [
    (EXACT, "exact"), (RANGE_IN, "range"), (RANGE_OUT, None), (ANY, "unspecified"),
    (PLATFORM_ONLY, None), (OTHER_VERSION, None),
])
def test_match_confidence(item, expected):
    assert nvd.match_confidence(item, "13.0") == expected


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, cves, page_size):
        self.cves, self.page_size, self.calls = cves, page_size, []

    def get(self, url, params, headers, timeout):
        self.calls.append(dict(params))
        start = params["startIndex"]
        page = self.cves[start:start + self.page_size]
        return FakeResponse(200, {"totalResults": len(self.cves),
                                  "vulnerabilities": [{"cve": c} for c in page]})


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    monkeypatch.delenv("NVD_API_KEY", raising=False)


def test_context_pages_filters_sorts_and_caches(monkeypatch):
    monkeypatch.setattr(nvd, "PAGE_SIZE", 2)
    session = FakeSession([EXACT, RANGE_IN, RANGE_OUT, ANY, PLATFORM_ONLY, OTHER_VERSION], 2)
    r = nvd.android_platform_context("13.0", session=session)
    assert [c["startIndex"] for c in session.calls] == [0, 2, 4]
    assert r["nvd_candidates"] == 6
    assert r["match_counts"] == {"exact": 1, "range": 1, "unspecified": 1}
    assert [c["cve_id"] for c in r["top_cves"]] == ["CVE-B", "CVE-A"]  # sorted by CVSS
    assert r["top_cves"][0]["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-B"
    assert r["from_cache"] is False and "not endorsed" in r["notice"]

    again = nvd.android_platform_context("13.0", session=session)
    assert again["from_cache"] is True
    assert len(session.calls) == 3


def test_rejects_unsupported_version():
    with pytest.raises(ValueError):
        nvd.android_platform_context("13.0'; DROP")


def test_retries_then_raises():
    class Failing:
        calls = 0

        def get(self, *a, **k):
            Failing.calls += 1
            return FakeResponse(503)
    with pytest.raises(nvd.NVDError):
        nvd.android_platform_context("14.0", session=Failing())
    assert Failing.calls == 3


def test_api_key_sent_as_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    seen = {}

    class Capture(FakeSession):
        def get(self, url, params, headers, timeout):
            seen.update(headers)
            return super().get(url, params, headers, timeout)
    nvd.android_platform_context("15.0", session=Capture([EXACT], 500))
    assert seen == {"apiKey": "test-key"}


def test_route_validation_and_failure(monkeypatch):
    import banking_app
    c = banking_app.app.test_client()
    with c.session_transaction() as s:
        s["username"] = "analyst"
    assert c.get("/api/mobile/vulnerabilities?android_version=99").status_code == 422

    def boom(version):
        raise nvd.NVDError("NVD request failed (HTTP 503)")
    monkeypatch.setattr(nvd, "android_platform_context", boom)
    r = c.get("/api/mobile/vulnerabilities?android_version=13.0")
    assert r.status_code == 503
    assert "Malware assessment is unaffected" in r.get_json()["error"]
