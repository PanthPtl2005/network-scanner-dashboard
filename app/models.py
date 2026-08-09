"""
app/models.py — SQLAlchemy ORM models: Scan, Host, Port
"""
from datetime import datetime, timezone
from app import db


class Scan(db.Model):
    __tablename__ = "scans"

    id          = db.Column(db.Integer, primary_key=True)
    subnet      = db.Column(db.String(64), nullable=False)
    scan_type   = db.Column(db.String(20), default="quick")   # quick | deep | full
    status      = db.Column(db.String(20), default="pending") # pending|running|done|error
    progress    = db.Column(db.Integer, default=0)             # 0-100 %
    started_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = db.Column(db.DateTime, nullable=True)
    error_msg   = db.Column(db.Text, nullable=True)
    hosts_up    = db.Column(db.Integer, default=0)
    total_ports = db.Column(db.Integer, default=0)
    high_risk   = db.Column(db.Integer, default=0)
    medium_risk = db.Column(db.Integer, default=0)
    low_risk    = db.Column(db.Integer, default=0)

    hosts = db.relationship("Host", back_populates="scan",
                            cascade="all, delete-orphan", lazy="dynamic")

    def duration_seconds(self):
        if self.finished_at and self.started_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None

    def to_dict(self):
        return {
            "id":          self.id,
            "subnet":      self.subnet,
            "scan_type":   self.scan_type,
            "status":      self.status,
            "progress":    self.progress,
            "started_at":  self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration":    self.duration_seconds(),
            "hosts_up":    self.hosts_up,
            "total_ports": self.total_ports,
            "high_risk":   self.high_risk,
            "medium_risk": self.medium_risk,
            "low_risk":    self.low_risk,
            "error_msg":   self.error_msg,
        }


class Host(db.Model):
    __tablename__ = "hosts"

    id         = db.Column(db.Integer, primary_key=True)
    scan_id    = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    hostname   = db.Column(db.String(256), nullable=True)
    status     = db.Column(db.String(20), default="up")
    os_name    = db.Column(db.String(256), nullable=True)
    os_accuracy= db.Column(db.Integer, nullable=True)
    mac_address= db.Column(db.String(20), nullable=True)
    vendor     = db.Column(db.String(128), nullable=True)
    risk_level = db.Column(db.String(10), default="low")   # high|medium|low
    risk_score = db.Column(db.Integer, default=0)
    open_ports = db.Column(db.Integer, default=0)
    cve_count  = db.Column(db.Integer, default=0)

    scan  = db.relationship("Scan", back_populates="hosts")
    ports = db.relationship("Port", back_populates="host",
                            cascade="all, delete-orphan", lazy="select")

    def to_dict(self, include_ports=False):
        d = {
            "id":          self.id,
            "scan_id":     self.scan_id,
            "ip_address":  self.ip_address,
            "hostname":    self.hostname,
            "status":      self.status,
            "os_name":     self.os_name,
            "os_accuracy": self.os_accuracy,
            "mac_address": self.mac_address,
            "vendor":      self.vendor,
            "risk_level":  self.risk_level,
            "risk_score":  self.risk_score,
            "open_ports":  self.open_ports,
            "cve_count":   self.cve_count,
        }
        if include_ports:
            d["ports"] = [p.to_dict() for p in self.ports]
        return d


class Port(db.Model):
    __tablename__ = "ports"

    id          = db.Column(db.Integer, primary_key=True)
    host_id     = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol    = db.Column(db.String(10), default="tcp")
    state       = db.Column(db.String(20), default="open")
    service     = db.Column(db.String(128), nullable=True)
    product     = db.Column(db.String(256), nullable=True)
    version     = db.Column(db.String(128), nullable=True)
    extra_info  = db.Column(db.String(256), nullable=True)
    cpe         = db.Column(db.String(256), nullable=True)
    banner      = db.Column(db.Text, nullable=True)
    risk_level  = db.Column(db.String(10), default="low")

    host = db.relationship("Host", back_populates="ports")

    def to_dict(self):
        return {
            "id":          self.id,
            "host_id":     self.host_id,
            "port_number": self.port_number,
            "protocol":    self.protocol,
            "state":       self.state,
            "service":     self.service,
            "product":     self.product,
            "version":     self.version,
            "extra_info":  self.extra_info,
            "cpe":         self.cpe,
            "banner":      self.banner,
            "risk_level":  self.risk_level,
        }
