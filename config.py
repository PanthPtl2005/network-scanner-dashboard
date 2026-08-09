"""
config.py — Application configuration settings
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    # ── Database ──────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'scans', 'netscan.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Scan defaults ─────────────────────────────────────────────────────
    DEFAULT_SUBNET        = "192.168.1.0/24"
    MASSCAN_RATE          = 1000          # packets/sec (safe for most LANs)
    NMAP_TOP_PORTS        = 100           # quick mode
    NMAP_FULL_PORTS       = "1-65535"     # full mode
    SCAN_TIMEOUT          = 300           # seconds max per scan

    # ── Paths ─────────────────────────────────────────────────────────────
    SCAN_OUTPUT_DIR       = os.path.join(BASE_DIR, "scans")

    # ── Flask ─────────────────────────────────────────────────────────────
    SECRET_KEY            = os.environ.get("SECRET_KEY", "netscan-dev-secret-42")
    DEBUG                 = os.environ.get("FLASK_DEBUG", "1") == "1"

    # ── CVE / NVD ─────────────────────────────────────────────────────────
    NVD_API_URL           = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY           = os.environ.get("NVD_API_KEY", "")     # optional
    CVE_CACHE_TTL         = 3600          # 1 hour cache for CVE lookups

    # ── Risk Scoring ─────────────────────────────────────────────────────
    HIGH_RISK_PORTS   = {23, 445, 3389, 21, 1433, 3306, 5432, 5900, 6379, 27017}
    MEDIUM_RISK_PORTS = {22, 80, 443, 25, 53, 110, 143, 8080, 8443}
    LOW_RISK_PORTS    = set()   # everything else
