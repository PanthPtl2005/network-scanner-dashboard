"""
app/db.py — CRUD helpers wrapping SQLAlchemy session operations
"""
from datetime import datetime, timezone
from app import db
from app.models import Scan, Host, Port


# ── Scan CRUD ────────────────────────────────────────────────────────────────

def create_scan(subnet: str, scan_type: str = "quick") -> Scan:
    scan = Scan(subnet=subnet, scan_type=scan_type, status="pending")
    db.session.add(scan)
    db.session.commit()
    return scan


def get_scan(scan_id: int) -> Scan | None:
    return db.session.get(Scan, scan_id)


def list_scans(limit: int = 50) -> list[Scan]:
    return db.session.scalars(
        db.select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    ).all()


def update_scan_status(scan_id: int, **kwargs):
    scan = get_scan(scan_id)
    if not scan:
        return
    for k, v in kwargs.items():
        setattr(scan, k, v)
    db.session.commit()


def finish_scan(scan_id: int, error: str | None = None):
    scan = get_scan(scan_id)
    if not scan:
        return
    scan.finished_at = datetime.now(timezone.utc)
    scan.status      = "error" if error else "done"
    scan.error_msg   = error
    scan.progress    = 100
    # Aggregate stats
    hosts = db.session.scalars(db.select(Host).where(Host.scan_id == scan_id)).all()
    scan.hosts_up    = len([h for h in hosts if h.status == "up"])
    scan.total_ports = sum(h.open_ports for h in hosts)
    scan.high_risk   = len([h for h in hosts if h.risk_level == "high"])
    scan.medium_risk = len([h for h in hosts if h.risk_level == "medium"])
    scan.low_risk    = len([h for h in hosts if h.risk_level == "low"])
    db.session.commit()


def delete_scan(scan_id: int) -> bool:
    scan = get_scan(scan_id)
    if not scan:
        return False
    db.session.delete(scan)
    db.session.commit()
    return True


# ── Host CRUD ────────────────────────────────────────────────────────────────

def upsert_host(scan_id: int, ip: str, **kwargs) -> Host:
    host = db.session.scalars(
        db.select(Host).where(Host.scan_id == scan_id, Host.ip_address == ip)
    ).first()
    if not host:
        host = Host(scan_id=scan_id, ip_address=ip)
        db.session.add(host)
    for k, v in kwargs.items():
        setattr(host, k, v)
    db.session.commit()
    return host


def get_hosts(scan_id: int) -> list[Host]:
    return db.session.scalars(
        db.select(Host).where(Host.scan_id == scan_id).order_by(Host.ip_address)
    ).all()


# ── Port CRUD ────────────────────────────────────────────────────────────────

def upsert_port(host_id: int, port_number: int, protocol: str = "tcp", **kwargs) -> Port:
    port = db.session.scalars(
        db.select(Port).where(
            Port.host_id == host_id,
            Port.port_number == port_number,
            Port.protocol == protocol,
        )
    ).first()
    if not port:
        port = Port(host_id=host_id, port_number=port_number, protocol=protocol)
        db.session.add(port)
    for k, v in kwargs.items():
        setattr(port, k, v)
    db.session.commit()
    return port


# ── Stats ────────────────────────────────────────────────────────────────────

def get_global_stats() -> dict:
    total_scans = db.session.scalar(db.select(db.func.count()).select_from(Scan)) or 0
    total_hosts = db.session.scalar(db.select(db.func.count()).select_from(Host)) or 0
    total_ports = db.session.scalar(db.select(db.func.sum(Host.open_ports)).select_from(Host)) or 0
    high_risk   = db.session.scalar(
        db.select(db.func.count()).select_from(Host).where(Host.risk_level == "high")
    ) or 0
    return {
        "total_scans": total_scans,
        "total_hosts": total_hosts,
        "total_ports": int(total_ports),
        "high_risk":   high_risk,
    }
