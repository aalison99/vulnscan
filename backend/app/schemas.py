from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from .models import Scan

SCANNERS = ("vuln", "secret", "misconfig")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
DEFAULT_SCANNERS = ["vuln", "secret", "misconfig"]
DEFAULT_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

ScannerName = Literal["vuln", "secret", "misconfig"]
SeverityName = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        if v not in out:
            out.append(v)
    return out


class ScanCreate(BaseModel):
    scan_type: Literal["image", "repo"]
    target: str = Field(min_length=1, max_length=1024)
    scanners: list[ScannerName] = Field(default_factory=lambda: list(DEFAULT_SCANNERS), min_length=1)
    severities: list[SeverityName] = Field(default_factory=lambda: list(DEFAULT_SEVERITIES), min_length=1)

    @field_validator("scanners", "severities")
    @classmethod
    def _unique(cls, v):
        return _dedupe(v)


class ScanCreated(BaseModel):
    scan_id: str
    status: str


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class Vulnerability(BaseModel):
    id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: str
    title: str = ""
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    target: str = ""
    pkg_type: str = ""
    published_date: Optional[str] = None
    primary_url: Optional[str] = None
    references: list[str] = []
    remediation: str = ""


class Misconfiguration(BaseModel):
    id: str
    avd_id: Optional[str] = None
    type: str = ""
    title: str = ""
    description: str = ""
    message: str = ""
    severity: str
    target: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    provider: Optional[str] = None
    service: Optional[str] = None
    primary_url: Optional[str] = None
    references: list[str] = []
    remediation: str = ""


class Secret(BaseModel):
    rule_id: str
    category: str = ""
    title: str = ""
    severity: str
    target: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    match: str = ""
    remediation: str = ""


class ScanSummary(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    scanners: list[str]
    severities: list[str]
    error: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    severity_counts: SeverityCounts  # vulnerabilities only
    vulnerability_count: int = 0
    misconfig_count: int = 0
    secret_count: int = 0


class ScanDetail(ScanSummary):
    os: Optional[str] = None
    misconfig_severity_counts: SeverityCounts = SeverityCounts()
    secret_severity_counts: SeverityCounts = SeverityCounts()
    vulnerabilities: list[Vulnerability] = []
    misconfigurations: list[Misconfiguration] = []
    secrets: list[Secret] = []


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    return dt.replace(tzinfo=timezone.utc) if dt else None


def summary_from_model(scan: Scan) -> ScanSummary:
    counts = SeverityCounts(
        critical=scan.critical,
        high=scan.high,
        medium=scan.medium,
        low=scan.low,
        unknown=scan.unknown,
    )
    return ScanSummary(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        scanners=[s for s in scan.scanners.split(",") if s],
        severities=[s for s in scan.severities.split(",") if s],
        error=scan.error,
        created_at=_aware(scan.created_at),
        started_at=_aware(scan.started_at),
        finished_at=_aware(scan.finished_at),
        severity_counts=counts,
        vulnerability_count=sum(counts.model_dump().values()),
        misconfig_count=scan.misconfig_count,
        secret_count=scan.secret_count,
    )