"""
app/scanner.py — nmap + masscan subprocess integration + scan pipeline
"""
from __future__ import annotations

import os
import re
import json
import shutil
import logging
import subprocess
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Subnet validation ─────────────────────────────────────────────────────────
_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
)

def validate_subnet(subnet: str) -> bool:
    if not _CIDR_RE.match(subnet.strip()):
        return False
    parts = subnet.split("/")[0].split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# ── Tool availability ──────────────────────────────────────────────────────────
def _which(cmd: str) -> str | None:
    return shutil.which(cmd)

def nmap_available()    -> bool: return _which("nmap")    is not None
def masscan_available() -> bool: return _which("masscan") is not None


# ── masscan ───────────────────────────────────────────────────────────────────

def run_masscan(subnet: str, out_path: str, rate: int = 1000) -> list[dict]:
    """
    Fast SYN discovery with masscan.
    Returns list of {ip, ports:[{port,proto}]} or [] on failure.
    """
    if not masscan_available():
        logger.warning("masscan not found — skipping fast discovery")
        return []

    cmd = [
        "masscan", subnet,
        "--ports", "1-65535",
        "--rate",  str(rate),
        "-oJ",     out_path,
        "--wait",  "3",
    ]

    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning("masscan stderr: %s", result.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.error("masscan timed out")
        return []
    except Exception as e:
        logger.error("masscan error: %s", e)
        return []

    # Parse output
    from app.parser import parse_masscan_json
    return parse_masscan_json(out_path)


# ── nmap ──────────────────────────────────────────────────────────────────────

def run_nmap(
    target: str,
    out_xml: str,
    ports: str = "--top-ports 100",
    os_detect: bool = True,
    version_detect: bool = True,
) -> list[dict]:
    """
    Run nmap against target (IP, range, or subnet).
    Returns parsed host list from XML.
    """
    if not nmap_available():
        logger.warning("nmap not found")
        return []

    cmd = ["nmap", "-sV", "-Pn", "--open", "-oX", out_xml]

    if os_detect:
        cmd += ["-O", "--osscan-guess"]

    if version_detect:
        cmd += ["--version-intensity", "5"]

    # Port selection
    if "--top-ports" in ports or "-p" in ports:
        cmd += ports.split()
    else:
        cmd += [f"-p{ports}"]

    cmd.append(target)

    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0 and result.returncode != 1:
            logger.warning("nmap stderr: %s", result.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out for %s", target)
        return []
    except Exception as e:
        logger.error("nmap error: %s", e)
        return []

    from app.parser import parse_nmap_xml
    return parse_nmap_xml(out_xml)


# ── Pipeline ───────────────────────────────────────────────────────────────────

def run_scan_pipeline(scan_id: int, subnet: str, scan_type: str, app):
    """
    Full pipeline: masscan discovery → nmap deep scan → DB persist.
    Runs in a background thread. Requires Flask app context.
    """
    def _run():
        with app.app_context():
            from app.crud import update_scan_status, upsert_host, upsert_port, finish_scan
            from app.utils import score_host, score_port, get_service_risk_label
            import app as app_pkg

            scan_dir = app.config["SCAN_OUTPUT_DIR"]
            ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            masscan_out = os.path.join(scan_dir, f"masscan_{scan_id}_{ts}.json")
            nmap_out    = os.path.join(scan_dir, f"nmap_{scan_id}_{ts}.xml")

            try:
                # ── Step 1: Update status ───────────────────────────────────
                update_scan_status(scan_id, status="running", progress=5)

                # ── Step 2: masscan fast discovery ──────────────────────────
                live_ips: list[str] = []
                if masscan_available():
                    logger.info("[scan %d] masscan starting...", scan_id)
                    rate = app.config.get("MASSCAN_RATE", 1000)
                    masscan_results = run_masscan(subnet, masscan_out, rate=rate)
                    live_ips = list({r["ip"] for r in masscan_results})
                    logger.info("[scan %d] masscan found %d IPs", scan_id, len(live_ips))
                    update_scan_status(scan_id, progress=30)
                else:
                    logger.warning("[scan %d] masscan unavailable, using nmap only", scan_id)
                    update_scan_status(scan_id, progress=20)

                # ── Step 3: nmap deep scan ──────────────────────────────────
                logger.info("[scan %d] nmap starting...", scan_id)
                update_scan_status(scan_id, progress=35)

                if scan_type == "quick":
                    port_arg = "--top-ports 100"
                elif scan_type == "deep":
                    port_arg = "--top-ports 1000"
                else:  # full
                    port_arg = "-p1-65535"

                nmap_target = " ".join(live_ips) if live_ips else subnet
                nmap_results = run_nmap(
                    nmap_target,
                    nmap_out,
                    ports=port_arg,
                    os_detect=(scan_type in ("deep", "full")),
                )

                update_scan_status(scan_id, progress=75)

                # ── Step 4: Persist to DB ───────────────────────────────────
                for host_data in nmap_results:
                    if host_data["status"] != "up":
                        continue

                    open_port_nums = [
                        p["port"] for p in host_data["ports"] if p["state"] == "open"
                    ]
                    risk_level, risk_score = score_host(open_port_nums)

                    host = upsert_host(
                        scan_id,
                        host_data["ip"],
                        hostname   = host_data.get("hostname") or None,
                        status     = host_data["status"],
                        os_name    = host_data.get("os_name"),
                        os_accuracy= host_data.get("os_accuracy"),
                        mac_address= host_data.get("mac") or None,
                        vendor     = host_data.get("vendor") or None,
                        risk_level = risk_level,
                        risk_score = risk_score,
                        open_ports = len(open_port_nums),
                    )

                    for p in host_data["ports"]:
                        if p["state"] != "open":
                            continue
                        port_risk, _ = score_port(p["port"])
                        svc_risk     = get_service_risk_label(p.get("service", ""))
                        best_risk    = "high" if "high" in (port_risk, svc_risk) else \
                                       "medium" if "medium" in (port_risk, svc_risk) else "low"
                        upsert_port(
                            host.id,
                            p["port"],
                            p.get("protocol", "tcp"),
                            state      = p["state"],
                            service    = p.get("service", ""),
                            product    = p.get("product", ""),
                            version    = p.get("version", ""),
                            extra_info = p.get("extra_info", ""),
                            cpe        = p.get("cpe", ""),
                            risk_level = best_risk,
                        )

                update_scan_status(scan_id, progress=95)
                finish_scan(scan_id)
                logger.info("[scan %d] completed successfully", scan_id)

            except Exception as exc:
                logger.exception("[scan %d] pipeline error: %s", scan_id, exc)
                finish_scan(scan_id, error=str(exc))

    thread = threading.Thread(target=_run, daemon=True, name=f"scan-{scan_id}")
    thread.start()
    return thread
