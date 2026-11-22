from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite drops tzinfo anyway)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(1024))
    scan_type: Mapped[str] = mapped_column(String(16))  # image | repo | fs
    status: Mapped[str] = mapped_column(String(16), index=True)  # queued|running|completed|failed
    scanners: Mapped[str] = mapped_column(String(64))  # csv: vuln,secret,misconfig
    severities: Mapped[str] = mapped_column(String(64))  # csv
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Vulnerability severity counts
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    unknown: Mapped[int] = mapped_column(Integer, default=0)

    misconfig_count: Mapped[int] = mapped_column(Integer, default=0)
    secret_count: Mapped[int] = mapped_column(Integer, default=0)

    # Raw JSON report. Deferred so list queries stay cheap; use undefer() to load.
    report_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True, deferred=True)