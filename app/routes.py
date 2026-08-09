"""
app/routes.py — All Flask routes and REST API endpoints
"""
from __future__ import annotations

import re
import json
import csv
import io
import logging
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, request, jsonify,
    abort, make_response, current_app,
)

from app.crud import (
    create_scan, get_scan, list_scans, update_scan_status,
    delete_scan, get_hosts, get_global_stats, upsert_host,
)
from app.models import Host, Port, Scan
from app import db
import sqlalchemy as sa
from app.scanner import run_scan_pipeline, validate_subnet, nmap_available, masscan_available
from app.utils import lookup_cves, format_duration

bp = Blueprint("main", __name__)
logger = logging.getLogger(__name__)


# ── Page Routes ──────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    scans = list_scans(10)
    stats = get_global_stats()
    return render_template(
        "index.html",
        scans=scans,
        stats=stats,
        nmap_ok=nmap_available(),
        masscan_ok=masscan_available(),
    )


# ── API: Scan Management ─────────────────────────────────────────────────────

@bp.route("/api/scan", methods=["POST"])
def api_start_scan():
    data   = request.get_json(force=True, silent=True) or {}
    subnet = data.get("subnet", "").strip()
    stype  = data.get("scan_type", "quick").lower()

    if not subnet:
        return jsonify({"error": "subnet is required"}), 400
    if not validate_subnet(subnet):
        return jsonify({"error": f"Invalid subnet: {subnet}"}), 400
    if stype not in ("quick", "deep", "full"):
        stype = "quick"

    scan = create_scan(subnet, stype)
    app  = current_app._get_current_object()  # de-proxy for thread
    run_scan_pipeline(scan.id, subnet, stype, app)

    return jsonify({"scan_id": scan.id, "status": "started"}), 202


@bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan.to_dict())


@bp.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    ok = delete_scan(scan_id)
    if not ok:
        return jsonify({"error": "not found"}), 404
    return jsonify({"deleted": scan_id})


@bp.route("/api/scans", methods=["GET"])
def api_list_scans():
    limit = min(int(request.args.get("limit", 20)), 100)
    scans = list_scans(limit)
    return jsonify([s.to_dict() for s in scans])


# ── API: Hosts ────────────────────────────────────────────────────────────────

@bp.route("/api/scan/<int:scan_id>/hosts", methods=["GET"])
def api_get_hosts(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    hosts = get_hosts(scan_id)
    return jsonify([h.to_dict(include_ports=True) for h in hosts])


@bp.route("/api/host/<int:host_id>", methods=["GET"])
def api_get_host(host_id):
    host = db.session.get(Host, host_id)
    if not host:
        return jsonify({"error": "not found"}), 404
    return jsonify(host.to_dict(include_ports=True))


# ── API: CVE Lookup ───────────────────────────────────────────────────────────

@bp.route("/api/cve", methods=["GET"])
def api_cve_lookup():
    service = request.args.get("service", "").strip()
    version = request.args.get("version", "").strip() or None
    if not service:
        return jsonify({"error": "service param required"}), 400
    cves = lookup_cves(service, version)
    return jsonify({"service": service, "version": version, "cves": cves, "count": len(cves)})


# ── API: Stats ────────────────────────────────────────────────────────────────

@bp.route("/api/stats", methods=["GET"])
def api_stats():
    stats = get_global_stats()
    # Port frequency top-10
    port_freq = db.session.execute(
        sa.select(Port.port_number, sa.func.count().label("cnt"))
        .group_by(Port.port_number)
        .order_by(sa.text("cnt DESC"))
        .limit(10)
    ).all()
    stats["port_frequency"] = [{"port": r[0], "count": r[1]} for r in port_freq]

    # Service distribution
    svc_freq = db.session.execute(
        sa.select(Port.service, sa.func.count().label("cnt"))
        .where(Port.service != "")
        .group_by(Port.service)
        .order_by(sa.text("cnt DESC"))
        .limit(8)
    ).all()
    stats["service_distribution"] = [{"service": r[0], "count": r[1]} for r in svc_freq]

    return jsonify(stats)


# ── API: Export ───────────────────────────────────────────────────────────────

@bp.route("/api/scan/<int:scan_id>/export/json", methods=["GET"])
def export_json(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    hosts = get_hosts(scan_id)
    payload = {
        "scan":  scan.to_dict(),
        "hosts": [h.to_dict(include_ports=True) for h in hosts],
    }
    resp = make_response(json.dumps(payload, indent=2))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.json"'
    return resp


@bp.route("/api/scan/<int:scan_id>/export/csv", methods=["GET"])
def export_csv(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    hosts = get_hosts(scan_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Hostname", "Status", "OS", "Open Ports",
                     "Risk Level", "Risk Score", "Ports List"])
    for h in hosts:
        ports_str = ", ".join(
            f"{p.port_number}/{p.protocol}({p.service})" for p in h.ports
        )
        writer.writerow([
            h.ip_address, h.hostname or "", h.status, h.os_name or "",
            h.open_ports, h.risk_level, h.risk_score, ports_str,
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv"'
    return resp


# ── API: System Info ──────────────────────────────────────────────────────────

@bp.route("/api/system", methods=["GET"])
def api_system():
    return jsonify({
        "nmap_available":    nmap_available(),
        "masscan_available": masscan_available(),
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    })


# ── Demo data injector (dev helper) ──────────────────────────────────────────

@bp.route("/api/demo", methods=["POST"])
def api_inject_demo():
    """Inject demo scan data so the dashboard renders even without nmap."""
    import random
    from app.crud import upsert_port, finish_scan
    from app.utils import score_host, score_port

    DEMO_HOSTS = [
        {"ip": "192.168.1.1",   "hostname": "gateway.local",  "os": "Linux 5.x", "ports": [80, 443, 22]},
        {"ip": "192.168.1.10",  "hostname": "desktop-1.local","os": "Windows 11", "ports": [3389, 445, 135, 80]},
        {"ip": "192.168.1.20",  "hostname": "nas.local",       "os": "FreeNAS",   "ports": [22, 80, 443, 9000]},
        {"ip": "192.168.1.30",  "hostname": "printer.local",   "os": "Embedded",  "ports": [80, 9100, 443]},
        {"ip": "192.168.1.50",  "hostname": "pi.local",        "os": "Raspbian",  "ports": [22, 8080, 1883]},
        {"ip": "192.168.1.100", "hostname": "server-1.local",  "os": "Ubuntu 22", "ports": [22, 80, 443, 3306, 6379]},
        {"ip": "192.168.1.110", "hostname": "server-2.local",  "os": "CentOS 7",  "ports": [22, 23, 21, 8080]},
        {"ip": "192.168.1.200", "hostname": "camera.local",    "os": "RTSP/ONVIF","ports": [80, 554, 8554]},
    ]
    SERVICE_MAP = {
        22: ("ssh","OpenSSH","8.9p1"), 80: ("http","nginx","1.24.0"),
        443: ("https","OpenSSL","3.0"), 3389: ("ms-wbt-server","",""),
        445: ("microsoft-ds","",""), 135: ("msrpc","",""),
        21: ("ftp","vsftpd","3.0.5"), 3306: ("mysql","MySQL","8.0.33"),
        6379: ("redis","","7.0.12"), 23: ("telnet","",""),
        9100: ("jetdirect","",""), 8080: ("http-proxy","",""),
        8554: ("rtsp","",""), 554: ("rtsp",""), 1883: ("mqtt","",""),
        9000: ("portainer","",""), 9100: ("jetdirect","",""),
    }

    scan = create_scan("192.168.1.0/24", "deep")
    update_scan_status(scan.id, status="running", progress=50)

    from app.crud import upsert_port
    for hd in DEMO_HOSTS:
        rl, rs = score_host(hd["ports"])
        host = upsert_host(
            scan.id, hd["ip"],
            hostname=hd["hostname"], status="up",
            os_name=hd["os"], os_accuracy=random.randint(85, 99),
            risk_level=rl, risk_score=rs,
            open_ports=len(hd["ports"]),
        )
        for pn in hd["ports"]:
            svc = SERVICE_MAP.get(pn, ("unknown", "", ""))
            port_risk, _ = score_port(pn)
            upsert_port(
                host.id, pn, "tcp",
                state="open",
                service=svc[0], product=svc[1] if len(svc) > 1 else "",
                version=svc[2] if len(svc) > 2 else "",
                risk_level=port_risk,
            )

    finish_scan(scan.id)
    return jsonify({"scan_id": scan.id, "hosts": len(DEMO_HOSTS)}), 201
