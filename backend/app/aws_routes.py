"""Endpoints for `aws` scans: scored findings, status tracking, scan diff, CSV export."""

import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from awsscan.models import severity_label

from .database import get_session
from .models import AwsFinding, Scan
from .schemas import FindingStatusUpdate

router = APIRouter(prefix="/api")

_SORTS = {"risk": AwsFinding.risk_score.desc(), "severity": AwsFinding.base_severity.desc()}


def _out(row: AwsFinding) -> dict:
    d = json.loads(row.data)
    d["id"] = row.id
    d["scan_id"] = row.scan_id
    d["status"] = row.status
    d["flat_severity"] = severity_label(row.base_severity)
    return d


async def _require_aws_scan(session: AsyncSession, scan_id: str) -> Scan:
    scan = (await session.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.scan_type != "aws":
        raise HTTPException(409, "Not an aws scan")
    return scan


@router.get("/scans/{scan_id}/findings")
async def list_findings(
    scan_id: str,
    category: Optional[str] = None,
    environment: Optional[str] = None,
    exposure: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(open|acknowledged|fixed|accepted-risk)$"),
    min_risk: float = Query(0, ge=0, le=100),
    sort: str = Query("risk", pattern="^(risk|severity)$"),
    limit: int = Query(1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """sort=risk is the context-aware ranking; sort=severity is the flat baseline."""
    await _require_aws_scan(session, scan_id)
    stmt = select(AwsFinding).where(AwsFinding.scan_id == scan_id, AwsFinding.risk_score >= min_risk)
    for col, val in ((AwsFinding.category, category), (AwsFinding.environment, environment),
                     (AwsFinding.exposure, exposure), (AwsFinding.status, status)):
        if val:
            stmt = stmt.where(col == val)
    stmt = stmt.order_by(_SORTS[sort], AwsFinding.risk_score.desc()).limit(limit)
    return [_out(r) for r in (await session.execute(stmt)).scalars()]


@router.get("/scans/{scan_id}/aws-report")
async def aws_report(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Account id, bucket summary and the services that could not be assessed."""
    await _require_aws_scan(session, scan_id)
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id).options(undefer(Scan.report_json)))).scalar_one()
    return json.loads(scan.report_json) if scan.report_json else {"summary": {}, "not_assessed": []}


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, body: FindingStatusUpdate,
                         session: AsyncSession = Depends(get_session)):
    row = (await session.execute(select(AwsFinding).where(AwsFinding.id == finding_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Finding not found")
    row.status = body.status
    await session.commit()
    return _out(row)


@router.get("/scans/{a}/diff/{b}")
async def diff_scans(a: str, b: str, session: AsyncSession = Depends(get_session)):
    """What changed from scan a (older) to scan b (newer): new, fixed, unchanged findings."""
    await _require_aws_scan(session, a)
    await _require_aws_scan(session, b)
    rows = {}
    for sid in (a, b):
        res = (await session.execute(select(AwsFinding).where(AwsFinding.scan_id == sid))).scalars()
        rows[sid] = {r.fingerprint: r for r in res}
    ka, kb = set(rows[a]), set(rows[b])
    return {
        "new": [_out(rows[b][k]) for k in sorted(kb - ka)],
        "fixed": [_out(rows[a][k]) for k in sorted(ka - kb)],
        "unchanged": [_out(rows[b][k]) for k in sorted(ka & kb)],
    }


_CSV = ["risk_score", "risk_bucket", "flat_severity", "category", "cis_id", "rule_id", "title",
        "resource_arn", "region", "environment", "exposure", "status", "remediation"]


def _cell(v):
    s = "" if v is None else str(v)
    return "'" + s if s and s[0] in "=+-@\t\r" else s  # neutralise spreadsheet formula injection


def findings_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: _cell(r.get(k)) for k in _CSV})
    return buf.getvalue()


@router.get("/scans/{scan_id}/findings/export")
async def export_findings(scan_id: str, session: AsyncSession = Depends(get_session)):
    await _require_aws_scan(session, scan_id)
    rows = (await session.execute(
        select(AwsFinding).where(AwsFinding.scan_id == scan_id).order_by(AwsFinding.risk_score.desc())
    )).scalars()
    return Response(findings_csv([_out(r) for r in rows]), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="aws-{scan_id[:8]}.csv"'})
