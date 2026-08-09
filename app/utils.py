"""
app/utils.py — Risk scoring and CVE lookup helpers
"""
from __future__ import annotations

import time
import logging
import requests
from functools import lru_cache
from flask import current_app

logger = logging.getLogger(__name__)

# ── Risk scoring ─────────────────────────────────────────────────────────────

HIGH_RISK_PORTS   = {23, 445, 3389, 21, 1433, 3306, 5432, 5900, 6379, 27017, 4444, 9200}
MEDIUM_RISK_PORTS = {22, 80, 443, 25, 53, 110, 143, 8080, 8443, 8888, 3000, 5000}


def score_port(port: int) -> tuple[str, int]:
    """
    Returns (risk_level, score_contribution) for a single port.
    high → 10, medium → 5, low → 1
    """
    if port in HIGH_RISK_PORTS:
        return "high", 10
    if port in MEDIUM_RISK_PORTS:
        return "medium", 5
    return "low", 1


def score_host(open_ports: list[int]) -> tuple[str, int]:
    """
    Aggregate host risk level + numeric score from its open port list.
    """
    if not open_ports:
        return "low", 0

    total = 0
    max_level = "low"
    level_order = {"low": 0, "medium": 1, "high": 2}

    for port in open_ports:
        lvl, pts = score_port(port)
        total += pts
        if level_order[lvl] > level_order[max_level]:
            max_level = lvl

    return max_level, total


# ── CVE Lookup ───────────────────────────────────────────────────────────────

_cve_cache: dict[str, tuple[list, float]] = {}
_CACHE_TTL = 3600  # 1 hour


def lookup_cves(service: str, version: str | None = None, max_results: int = 5) -> list[dict]:
    """
    Query NVD API for CVEs matching service+version.
    Returns a list of CVE dicts with id, description, severity.
    Falls back to empty list on any error.
    """
    if not service:
        return []

    query = service.strip().lower()
    if version:
        query = f"{query} {version.strip()}"

    cache_key = query
    now = time.time()
    if cache_key in _cve_cache:
        cached, ts = _cve_cache[cache_key]
        if now - ts < _CACHE_TTL:
            return cached

    try:
        api_key = ""
        try:
            api_key = current_app.config.get("NVD_API_KEY", "")
        except RuntimeError:
            pass  # outside app context

        headers = {"apiKey": api_key} if api_key else {}
        params = {
            "keywordSearch": query,
            "resultsPerPage": max_results,
        }
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            timeout=8,
        )
        if resp.status_code != 200:
            logger.warning("NVD API returned %s for query '%s'", resp.status_code, query)
            return []

        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(key, [])
                if ms:
                    cvss = ms[0].get("cvssData", {})
                    severity = cvss.get("baseSeverity", severity)
                    score    = cvss.get("baseScore", score)
                    break

            results.append({
                "id":          cve_id,
                "description": desc[:300],
                "severity":    severity,
                "score":       score,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        _cve_cache[cache_key] = (results, now)
        return results

    except Exception as e:
        logger.error("CVE lookup failed for '%s': %s", query, e)
        return []


def get_service_risk_label(service_name: str) -> str:
    """Quick mapping from common service names to risk labels."""
    sn = (service_name or "").lower()
    HIGH_SERVICES   = {"telnet", "ftp", "rdp", "smb", "ms-sql", "mysql",
                       "postgresql", "vnc", "redis", "mongodb", "elasticsearch"}
    MEDIUM_SERVICES = {"ssh", "http", "https", "smtp", "dns", "imap", "pop3"}
    if sn in HIGH_SERVICES:
        return "high"
    if sn in MEDIUM_SERVICES:
        return "medium"
    return "low"


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"
