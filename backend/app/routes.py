import asyncio
import csv
import io
import os
import re
import uuid
from pathlib import Path
from typing import Callable, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from . import scanner
from .config import settings
from .database import get_session
from .models import Scan, utcnow
from .parser import parse_report
from .schemas import (
    DEFAULT_SCANNERS,
    DEFAULT_SEVERITIES,
    SCANNERS,
    SEVERITIES,
    ScanCreate,
    ScanCreated,
    ScanDetail,
    ScanSummary,
    SeverityCounts,
    summary_from_model,
)

router = APIRouter(prefix="/api")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _get_scan(session: AsyncSession, scan_id: str, with_report: bool = False) -> Scan:
    stmt = select(Scan).where(Scan.id == scan_id)
    if with_report:
        stmt = stmt.options(undefer(Scan.report_json))
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


def _parse_choices(
    raw: str, allowed: tuple[str, ...], field: str, norm: Callable[[str], str]
) -> list[str]:
    items: list[str] = []
    for part in raw.split(","):
        part = norm(part.strip())
        if not part:
            continue
        if part not in allowed:
            raise HTTPException(422, f"Invalid {field}: {part}")
        if part not in items:
            items.append(part)
    if not items:
        raise HTTPException(422, f"At least one {field} is required")
    return items


def _archive_ext(filename: str) -> Optional[str]:
    name = filename.lower()
    for ext in (".tar.gz", ".tgz", ".zip"):
        if name.endswith(ext):
            return ext
    return None


def _safe_display_name(filename: str) -> str:
    name = os.path.basename(filename.replace("\\", "/"))
    return re.sub(r"[\x00-\x1f\x7f]", "", name)[:200] or "upload"


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
@router.post("/scans", response_model=ScanCreated, status_code=202)
async def create_scan(body: ScanCreate, session: AsyncSession = Depends(get_session)):
    try:
        target = scanner.validate_target(body.scan_type, body.target)
    except ValueError as e:
        raise HTTPException(422, str(e))

    scan = Scan(
        id=str(uuid.uuid4()),
        target=target,
        scan_type=body.scan_type,
        status="queued",
        scanners=",".join(body.scanners),
        severities=",".join(body.severities),
        created_at=utcnow(),
    )
    session.add(scan)
    await session.commit()

    scanner.launch(scan.id)
    return ScanCreated(scan_id=scan.id, status=scan.status)


@router.post("/scans/upload", response_model=ScanCreated, status_code=202)
async def upload_scan(
    file: UploadFile = File(...),
    scanners: str = Form(",".join(DEFAULT_SCANNERS)),
    severities: str = Form(",".join(DEFAULT_SEVERITIES)),
    session: AsyncSession = Depends(get_session),
):
    filename = file.filename or ""
    ext = _archive_ext(filename)
    if ext is None:
        raise HTTPException(422, "Only .zip, .tar.gz and .tgz archives are supported")

    scanner_list = _parse_choices(scanners, SCANNERS, "scanner", str.lower)
    severity_list = _parse_choices(severities, SEVERITIES, "severity", str.upper)

    scan_id = str(uuid.uuid4())
    dest = Path(settings.upload_dir) / f"{scan_id}{ext}"
    limit = settings.max_upload_mb * 1024 * 1024
    size = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(
                        413, f"Archive exceeds the {settings.max_upload_mb} MB upload limit"
                    )
                await asyncio.to_thread(out.write, chunk)
        if size == 0:
            raise HTTPException(400, "Uploaded file is empty")
    except BaseException:
        dest.unlink(missing_ok=True)
        raise

    scan = Scan(
        id=scan_id,
        target=_safe_display_name(filename),
        scan_type="fs",
        status="queued",
        scanners=",".join(scanner_list),
        severities=",".join(severity_list),
        created_at=utcnow(),
    )
    session.add(scan)
    await session.commit()

    scanner.launch(scan_id, upload_path=str(dest))
    return ScanCreated(scan_id=scan_id, status=scan.status)


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
    ).scalars().all()
    return [summary_from_model(r) for r in rows]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    scan = await _get_scan(session, scan_id, with_report=True)
    summary = summary_from_model(scan)

    if not scan.report_json:
        return ScanDetail(**summary.model_dump())

    parsed = await asyncio.to_thread(parse_report, scan.report_json)
    return ScanDetail(
        **summary.model_dump(),
        os=parsed.os,
        misconfig_severity_counts=SeverityCounts(**parsed.misconfig_counts),
        secret_severity_counts=SeverityCounts(**parsed.secret_counts),
        vulnerabilities=parsed.vulnerabilities,
        misconfigurations=parsed.misconfigurations,
        secrets=parsed.secrets,
    )


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    scan = await _get_scan(session, scan_id)
    scanner.cancel_scan(scan_id)
    await session.delete(scan)
    await session.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
_CSV_FIELDS = [
    "category", "severity", "id", "title", "package", "installed_version",
    "fixed_version", "cvss_score", "target", "start_line", "end_line",
    "primary_url", "description",
]


def _cell(value):
    """Neutralize spreadsheet formula injection from untrusted scan content."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    s = str(value)
    return "'" + s if s and s[0] in "=+-@\t\r" else s


def _build_csv(parsed) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS)
    writer.writeheader()

    for v in parsed.vulnerabilities:
        writer.writerow({k: _cell(x) for k, x in {
            "category": "vulnerability", "severity": v.severity, "id": v.id,
            "title": v.title, "package": v.pkg_name,
            "installed_version": v.installed_version, "fixed_version": v.fixed_version,
            "cvss_score": v.cvss_score, "target": v.target,
            "primary_url": v.primary_url, "description": v.description,
        }.items()})
    for m in parsed.misconfigurations:
        writer.writerow({k: _cell(x) for k, x in {
            "category": "misconfiguration", "severity": m.severity, "id": m.id,
            "title": m.title, "target": m.target, "start_line": m.start_line,
            "end_line": m.end_line, "primary_url": m.primary_url,
            "description": m.message or m.description,
        }.items()})
    for s in parsed.secrets:
        writer.writerow({k: _cell(x) for k, x in {
            "category": "secret", "severity": s.severity, "id": s.rule_id,
            "title": s.title, "target": s.target, "start_line": s.start_line,
            "end_line": s.end_line, "description": s.match,
        }.items()})
    return buf.getvalue()


@router.get("/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|csv)$"),
    session: AsyncSession = Depends(get_session),
):
    scan = await _get_scan(session, scan_id, with_report=True)
    if not scan.report_json:
        raise HTTPException(409, "No report available for this scan")

    base = f"vulnscan-{scan.id[:8]}"
    if fmt == "json":
        return Response(
            content=scan.report_json,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
        )

    parsed = await asyncio.to_thread(parse_report, scan.report_json)
    content = await asyncio.to_thread(_build_csv, parsed)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{base}.csv"'},
    )


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
@router.get("/health")
async def health():
    version, server = await asyncio.gather(
        scanner.get_scanner_version(), scanner.check_server()
    )
    ok = version["ok"] and server["reachable"]
    return {
        "status": "ok" if ok else "degraded",
        "backend": "ok",
        "scanner": version,
        "scanner_server": server,
    }