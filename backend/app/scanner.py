"""Runs vulnscan as a subprocess (never through a shell) and tracks scan jobs."""

import asyncio
import contextlib
import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, update

from .config import settings
from .database import SessionLocal
from .models import Scan, utcnow
from .parser import parse_report
from .schemas import DEFAULT_SEVERITIES

log = logging.getLogger("vulnscan.scanner")

_IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,511}")
_CONTROL_RE = re.compile(r"[\s\x00-\x1f\x7f]")

_semaphore: Optional[asyncio.Semaphore] = None
_tasks: dict[str, asyncio.Task] = {}
_version_cache: Optional[str] = None


class ScanError(Exception):
    """A scan failed in an expected way; the message is shown to the user."""


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_target(scan_type: str, target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target is required")

    if scan_type == "image":
        if not _IMAGE_RE.fullmatch(target):
            raise ValueError("Invalid container image reference")
    elif scan_type == "repo":
        if _CONTROL_RE.search(target):
            raise ValueError("Repository URL must not contain whitespace")
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Repository URL must start with http:// or https://")
        if parsed.username or parsed.password:
            raise ValueError("Credentials in repository URLs are not supported")
    else:
        raise ValueError("Unsupported scan type")
    return target


# --------------------------------------------------------------------------- #
# Command construction + execution
# --------------------------------------------------------------------------- #
def build_command(
    scan_type: str,
    target: str,
    scanners: list[str],
    severities: list[str],
    output_path: str,
) -> list[str]:
    """Single place that defines how vulnscan is invoked."""
    cmd = [
        settings.scanner_bin,
        scan_type,  # image | repo | fs
        "--server", settings.server_url,
        "--format", "json",
        "--output", output_path,
        "--scanners", ",".join(scanners),
        "--timeout", f"{settings.scan_timeout_seconds}s",
        "--quiet",
        "--skip-version-check",
    ]
    # All four selected means "no filter" (also keeps UNKNOWN findings).
    if severities and not set(DEFAULT_SEVERITIES) <= set(severities):
        cmd += ["--severity", ",".join(severities)]
    cmd.append(target)
    return cmd


def _error_text(stderr: bytes, code: int) -> str:
    text = re.sub(r"\x1b\[[0-9;]*m", "", stderr.decode(errors="replace"))
    lines = [ln for ln in text.splitlines() if ln.strip()]
    important = [ln for ln in lines if "FATAL" in ln or "ERROR" in ln]
    chosen = important[-5:] if important else lines[-10:]
    msg = "\n".join(chosen).strip()
    return (msg or f"vulnscan exited with code {code}")[-1500:]


async def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()


async def _exec(cmd: list[str]) -> None:
    env = {**os.environ, "NO_COLOR": "1"}
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    timeout = settings.scan_timeout_seconds + 30
    try:
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        await _kill(proc)
        raise ScanError(f"Scan timed out after {settings.scan_timeout_seconds}s")
    except BaseException:
        await _kill(proc)
        raise

    if proc.returncode != 0:
        raise ScanError(_error_text(stderr, proc.returncode))


# --------------------------------------------------------------------------- #
# Safe archive extraction
# --------------------------------------------------------------------------- #
def _safe_join(dest: str, name: str) -> str:
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ScanError(f"Archive contains an unsafe path: {name}")
    target = os.path.normpath(os.path.join(dest, name))
    if target != dest and not target.startswith(dest + os.sep):
        raise ScanError(f"Archive contains an unsafe path: {name}")
    return target


def _copy_limited(src, out, total: int, limit: int) -> int:
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return total
        total += len(chunk)
        if total > limit:
            raise ScanError(
                f"Archive expands beyond the {settings.max_extracted_mb} MB limit"
            )
        out.write(chunk)


def safe_extract(archive_path: str, dest: str) -> None:
    """Extract .zip / .tar.gz; skips links and special files, blocks traversal and bombs."""
    os.makedirs(dest, exist_ok=True)
    dest = os.path.realpath(dest)
    limit = settings.max_extracted_mb * 1024 * 1024
    max_files = settings.max_archive_files
    total = 0

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as zf:
                infos = zf.infolist()
                if len(infos) > max_files:
                    raise ScanError(f"Archive has more than {max_files} entries")
                for info in infos:
                    target = _safe_join(dest, info.filename)
                    if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                        continue  # symlink
                    if info.is_dir():
                        os.makedirs(target, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(info) as src, open(target, "wb") as out:
                        total = _copy_limited(src, out, total, limit)
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as tf:
                count = 0
                for member in tf:
                    count += 1
                    if count > max_files:
                        raise ScanError(f"Archive has more than {max_files} entries")
                    target = _safe_join(dest, member.name)
                    if member.isdir():
                        os.makedirs(target, exist_ok=True)
                        continue
                    if not member.isreg():
                        continue  # symlinks, hardlinks, devices, fifos
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with src, open(target, "wb") as out:
                        total = _copy_limited(src, out, total, limit)
        else:
            raise ScanError("File is not a valid .zip or .tar.gz archive")
    except (zipfile.BadZipFile, tarfile.TarError, RuntimeError, EOFError, OSError) as e:
        raise ScanError(f"Could not extract archive: {e}") from e


# --------------------------------------------------------------------------- #
# Job orchestration
# --------------------------------------------------------------------------- #
def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
    return _semaphore


async def _update(scan_id: str, **values) -> None:
    """Update a scan row; silently does nothing if it was deleted."""
    async with SessionLocal() as session:
        await session.execute(update(Scan).where(Scan.id == scan_id).values(**values))
        await session.commit()


async def _get_params(scan_id: str):
    async with SessionLocal() as session:
        res = await session.execute(
            select(Scan.scan_type, Scan.target, Scan.scanners, Scan.severities).where(
                Scan.id == scan_id
            )
        )
        return res.one_or_none()


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


async def _run(scan_id: str, upload_path: Optional[str]) -> None:
    workdir: Optional[str] = None
    try:
        async with _get_semaphore():
            params = await _get_params(scan_id)
            if params is None:
                return  # deleted while queued
            scan_type, target, scanners_csv, severities_csv = params
            scanners = [s for s in scanners_csv.split(",") if s]
            severities = [s for s in severities_csv.split(",") if s]

            await _update(scan_id, status="running", started_at=utcnow())
            workdir = tempfile.mkdtemp(prefix=f"scan-{scan_id[:8]}-", dir=settings.tmp_dir)

            run_target = target
            if scan_type == "fs":
                if not upload_path:
                    raise ScanError("Uploaded archive is missing")
                extract_dir = os.path.join(workdir, "src")
                await asyncio.to_thread(safe_extract, upload_path, extract_dir)
                run_target = extract_dir

            out_path = os.path.join(workdir, "report.json")
            cmd = build_command(scan_type, run_target, scanners, severities, out_path)
            log.info("scan %s: running %s scan", scan_id, scan_type)
            await _exec(cmd)

            if not os.path.exists(out_path):
                raise ScanError("vulnscan finished without producing a report")
            raw = await asyncio.to_thread(_read_text, out_path)
            parsed = await asyncio.to_thread(parse_report, raw)

            c = parsed.vuln_counts
            await _update(
                scan_id,
                status="completed",
                finished_at=utcnow(),
                error=None,
                critical=c["critical"],
                high=c["high"],
                medium=c["medium"],
                low=c["low"],
                unknown=c["unknown"],
                misconfig_count=len(parsed.misconfigurations),
                secret_count=len(parsed.secrets),
                report_json=raw,
            )
            log.info("scan %s: completed", scan_id)

    except asyncio.CancelledError:
        raise
    except ScanError as e:
        log.warning("scan %s failed: %s", scan_id, e)
        await _update(scan_id, status="failed", finished_at=utcnow(), error=str(e))
    except Exception as e:  # noqa: BLE001
        log.exception("scan %s crashed", scan_id)
        await _update(
            scan_id,
            status="failed",
            finished_at=utcnow(),
            error=f"Internal error: {type(e).__name__}: {e}"[:1500],
        )
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        if upload_path:
            with contextlib.suppress(OSError):
                os.remove(upload_path)


def launch(scan_id: str, upload_path: Optional[str] = None) -> None:
    task = asyncio.create_task(_run(scan_id, upload_path))
    _tasks[scan_id] = task
    task.add_done_callback(lambda _t, sid=scan_id: _tasks.pop(sid, None))


def cancel_scan(scan_id: str) -> None:
    task = _tasks.get(scan_id)
    if task and not task.done():
        task.cancel()


async def shutdown_tasks() -> None:
    tasks = list(_tasks.values())
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def recover_stale_scans() -> None:
    """Scans left queued/running by a previous process can never finish."""
    async with SessionLocal() as session:
        await session.execute(
            update(Scan)
            .where(Scan.status.in_(("queued", "running")))
            .values(
                status="failed",
                finished_at=utcnow(),
                error="Interrupted by a backend restart",
            )
        )
        await session.commit()
    for d in (settings.tmp_dir, settings.upload_dir):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Health helpers
# --------------------------------------------------------------------------- #
async def get_scanner_version() -> dict:
    global _version_cache
    if _version_cache:
        return {"ok": True, "version": _version_cache}
    try:
        proc = await asyncio.create_subprocess_exec(
            settings.scanner_bin,
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as e:
        return {"ok": False, "version": None, "error": str(e)}
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except asyncio.TimeoutError:
        await _kill(proc)
        return {"ok": False, "version": None, "error": "timed out"}
    text = out.decode(errors="replace").strip()
    if proc.returncode != 0:
        return {"ok": False, "version": None, "error": text[:300]}
    _version_cache = text.splitlines()[0] if text else "unknown"
    return {"ok": True, "version": _version_cache}


async def check_server() -> dict:
    result: dict = {"url": settings.server_url, "reachable": False}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{settings.server_url}/healthz")
            result["reachable"] = r.status_code < 500
            result["status_code"] = r.status_code
            try:
                v = await client.get(f"{settings.server_url}/version")
                if v.status_code == 200:
                    result["info"] = v.json()
            except (httpx.HTTPError, ValueError):
                pass
    except httpx.HTTPError as e:
        result["error"] = str(e) or type(e).__name__
    return result