"""
app/parser.py — Parse nmap XML output into structured Python dicts
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import logging
import os

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Parse an nmap XML output file.
    Returns a list of host dicts:
      {
        ip, hostname, status, os_name, os_accuracy, mac, vendor,
        ports: [{port, protocol, state, service, product, version, extra_info, cpe}]
      }
    """
    if not os.path.exists(xml_path):
        logger.error("nmap XML not found: %s", xml_path)
        return []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse nmap XML %s: %s", xml_path, e)
        return []

    hosts = []

    for host_el in root.findall("host"):
        # ── Status ──────────────────────────────────────────────────────────
        status_el = host_el.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"

        # ── IP / Hostname ────────────────────────────────────────────────────
        ip = ""
        hostname = ""
        mac = ""
        vendor = ""

        for addr_el in host_el.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype == "ipv4":
                ip = addr_el.get("addr", "")
            elif atype == "mac":
                mac    = addr_el.get("addr", "")
                vendor = addr_el.get("vendor", "")

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

        # ── OS Detection ─────────────────────────────────────────────────────
        os_name     = None
        os_accuracy = None
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch_el = os_el.find("osmatch")
            if osmatch_el is not None:
                os_name     = osmatch_el.get("name", "")
                os_accuracy = _safe_int(osmatch_el.get("accuracy", ""))

        # ── Ports ────────────────────────────────────────────────────────────
        ports_list = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                proto = port_el.get("protocol", "tcp")
                portid = _safe_int(port_el.get("portid", "0"))

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                svc_el  = port_el.find("service")
                service = product = version = extra_info = cpe_str = ""
                if svc_el is not None:
                    service    = svc_el.get("name", "")
                    product    = svc_el.get("product", "")
                    version    = svc_el.get("version", "")
                    extra_info = svc_el.get("extrainfo", "")
                    cpe_el     = svc_el.find("cpe")
                    if cpe_el is not None:
                        cpe_str = cpe_el.text or ""

                ports_list.append({
                    "port":       portid,
                    "protocol":   proto,
                    "state":      state,
                    "service":    service,
                    "product":    product,
                    "version":    version,
                    "extra_info": extra_info,
                    "cpe":        cpe_str,
                })

        if ip:
            hosts.append({
                "ip":          ip,
                "hostname":    hostname,
                "status":      status,
                "os_name":     os_name,
                "os_accuracy": os_accuracy,
                "mac":         mac,
                "vendor":      vendor,
                "ports":       ports_list,
            })

    logger.info("Parsed %d hosts from %s", len(hosts), xml_path)
    return hosts


def parse_masscan_json(json_path: str) -> list[dict]:
    """
    Parse masscan JSON output (-oJ flag).
    Returns list of {ip, ports: [{port, proto, status}]}
    """
    import json

    if not os.path.exists(json_path):
        logger.error("masscan JSON not found: %s", json_path)
        return []

    try:
        with open(json_path) as f:
            raw = f.read().strip()
        # masscan wraps output in invalid JSON — strip trailing comma + wrap
        if raw.endswith(","):
            raw = raw[:-1]
        if not raw.startswith("["):
            raw = f"[{raw}]"
        data = json.loads(raw)
    except Exception as e:
        logger.error("Failed to parse masscan JSON %s: %s", json_path, e)
        return []

    results = []
    for entry in data:
        ip    = entry.get("ip", "")
        ports = []
        for p in entry.get("ports", []):
            ports.append({
                "port":  p.get("port", 0),
                "proto": p.get("proto", "tcp"),
                "state": p.get("status", "open"),
            })
        if ip:
            results.append({"ip": ip, "ports": ports})

    return results


def _safe_int(val: str | None) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
