"""SQLite persistence for scans. One scanner process, bounded background execution."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64))
    configuration: Mapped[str] = mapped_column(String(32))
    origin: Mapped[str] = mapped_column(String(256))
    kind: Mapped[str] = mapped_column(String(16), default="manifest")  # manifest | autoscan
    status: Mapped[str] = mapped_column(String(16), index=True)  # queued|running|completed|cancelled|failed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requests_sent: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def to_summary(self) -> dict:
        result = self.result or {}
        counts = result.get("severity_counts", {})
        return {
            "id": self.id, "target_id": self.target_id, "configuration": self.configuration,
            "origin": self.origin, "kind": self.kind, "status": self.status,
            "created_at": _iso(self.created_at), "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at), "requests_sent": self.requests_sent,
            "error": self.error, "severity_counts": counts,
            "metrics": {
                "endpoints": len(result.get("endpoints", [])),
                "resources": (result.get("resources") or {}).get("total", 0),
                "tests": result.get("test_count", 0),
                "violations": sum(1 for f in result.get("findings", []) if f.get("confirmation") == "confirmed"),
            },
        }

    def to_detail(self) -> dict:
        return {**self.to_summary(), "result": self.result}


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    target_id: Mapped[str] = mapped_column(String(64))
    configuration: Mapped[str] = mapped_column(String(32))
    scan_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict] = mapped_column(JSON)

    def to_summary(self) -> dict:
        return {"id": self.id, "name": self.name, "target_id": self.target_id,
                "configuration": self.configuration, "scan_id": self.scan_id,
                "created_at": _iso(self.created_at),
                "violation_count": len((self.data or {}).get("violations", {}))}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


class Store:
    def __init__(self, url: str = "sqlite:///boundarylens.db"):
        self.engine = create_engine(url, connect_args={"check_same_thread": False})
        self._session = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return self._session()

    def recover_interrupted(self) -> int:
        """Mark scans left running/queued by a previous process as failed (interrupted)."""
        with self.session() as s:
            stale = s.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))).all()
            for scan in stale:
                scan.status = "failed"
                scan.error = "interrupted: scanner process restarted before this scan finished"
                scan.finished_at = datetime.now(timezone.utc)
            s.commit()
            return len(stale)

    def create(self, scan_id: str, target_id: str, configuration: str, origin: str,
               kind: str = "manifest") -> dict:
        with self.session() as s:
            scan = Scan(id=scan_id, target_id=target_id, configuration=configuration, origin=origin,
                        kind=kind, status="queued", created_at=datetime.now(timezone.utc))
            s.add(scan)
            s.commit()
            return scan.to_summary()

    # ---- baselines ----
    def create_baseline(self, baseline_id: str, name: str, target_id: str, configuration: str,
                        scan_id: str, data: dict) -> dict:
        with self.session() as s:
            row = Baseline(id=baseline_id, name=name, target_id=target_id, configuration=configuration,
                           scan_id=scan_id, created_at=datetime.now(timezone.utc), data=data)
            s.add(row)
            s.commit()
            return row.to_summary()

    def get_baseline(self, baseline_id: str) -> Baseline | None:
        with self.session() as s:
            return s.get(Baseline, baseline_id)

    def list_baselines(self, limit: int = 50) -> list[dict]:
        with self.session() as s:
            rows = s.scalars(select(Baseline).order_by(Baseline.created_at.desc()).limit(limit)).all()
            return [r.to_summary() for r in rows]

    def get(self, scan_id: str) -> Scan | None:
        with self.session() as s:
            return s.get(Scan, scan_id)

    def list(self, limit: int = 50) -> list[dict]:
        with self.session() as s:
            rows = s.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).all()
            return [r.to_summary() for r in rows]

    def update(self, scan_id: str, **fields) -> None:
        with self.session() as s:
            scan = s.get(Scan, scan_id)
            if not scan:
                return
            for key, value in fields.items():
                setattr(scan, key, value)
            s.commit()

    def latest_for_configuration(self, configuration: str) -> dict | None:
        with self.session() as s:
            row = s.scalars(select(Scan).where(Scan.configuration == configuration, Scan.status == "completed")
                            .order_by(Scan.created_at.desc()).limit(1)).first()
            return row.to_detail() if row else None
