"""Normalizes the JSON report produced by `vulnscan ... --format json`."""

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .schemas import Misconfiguration, Secret, Vulnerability

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

SECRET_REMEDIATION = (
    "Revoke and rotate this credential immediately, remove it from the codebase "
    "and git history, and load it from a secrets manager or environment variable."
)


@dataclass
class ParsedReport:
    os: Optional[str] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    misconfigurations: list[Misconfiguration] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    vuln_counts: dict[str, int] = field(default_factory=dict)
    misconfig_counts: dict[str, int] = field(default_factory=dict)
    secret_counts: dict[str, int] = field(default_factory=dict)


def _sev(value: Any) -> str:
    s = str(value or "").upper()
    return s if s in SEVERITY_ORDER else "UNKNOWN"


def _refs(primary: Optional[str], refs: Any, limit: int = 25) -> list[str]:
    out: list[str] = []
    for r in ([primary] if primary else []) + list(refs or []):
        if isinstance(r, str) and r and r not in out:
            out.append(r)
    return out[:limit]


def _best_cvss(cvss: Any) -> tuple[Optional[float], Optional[str]]:
    if not isinstance(cvss, dict) or not cvss:
        return None, None
    preferred = [k for k in ("nvd", "ghsa", "redhat") if k in cvss]
    sources = preferred + [k for k in cvss if k not in preferred]
    for key in ("V3", "V2"):
        for src in sources:
            entry = cvss.get(src) or {}
            score = entry.get(f"{key}Score")
            if score:
                return float(score), entry.get(f"{key}Vector")
    return None, None


def _vuln_remediation(pkg: str, fixed: Optional[str]) -> str:
    if fixed:
        return f"Upgrade {pkg} to a fixed version: {fixed}."
    return (
        f"No fixed version of {pkg} is available yet. Monitor upstream advisories, "
        "apply vendor mitigations, or consider replacing the package."
    )


def _counts(items: list[Any], attr: str = "severity") -> dict[str, int]:
    counts = {k.lower(): 0 for k in SEVERITY_ORDER}
    for item in items:
        counts[getattr(item, attr).lower()] += 1
    return counts


def parse_report(raw: Any) -> ParsedReport:
    data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    if not isinstance(data, dict):
        data = {}

    meta_os = (data.get("Metadata") or {}).get("OS") or {}
    os_str = " ".join(x for x in (meta_os.get("Family"), meta_os.get("Name")) if x) or None

    vulns: list[Vulnerability] = []
    misconfigs: list[Misconfiguration] = []
    secrets: list[Secret] = []

    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        res_type = result.get("Type") or result.get("Class") or ""

        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or None
            pkg = v.get("PkgName") or ""
            score, vector = _best_cvss(v.get("CVSS"))
            vulns.append(
                Vulnerability(
                    id=v.get("VulnerabilityID") or "UNKNOWN",
                    pkg_name=pkg,
                    installed_version=v.get("InstalledVersion") or "",
                    fixed_version=fixed,
                    severity=_sev(v.get("Severity")),
                    title=v.get("Title") or "",
                    description=v.get("Description") or "",
                    cvss_score=score,
                    cvss_vector=vector,
                    target=target,
                    pkg_type=res_type,
                    published_date=v.get("PublishedDate"),
                    primary_url=v.get("PrimaryURL"),
                    references=_refs(v.get("PrimaryURL"), v.get("References")),
                    remediation=_vuln_remediation(pkg, fixed),
                )
            )

        for m in result.get("Misconfigurations") or []:
            if str(m.get("Status") or "FAIL").upper() == "PASS":
                continue
            cause = m.get("CauseMetadata") or {}
            misconfigs.append(
                Misconfiguration(
                    id=m.get("ID") or "UNKNOWN",
                    avd_id=m.get("AVDID"),
                    type=m.get("Type") or res_type,
                    title=m.get("Title") or "",
                    description=m.get("Description") or "",
                    message=m.get("Message") or "",
                    severity=_sev(m.get("Severity")),
                    target=target,
                    start_line=cause.get("StartLine") or None,
                    end_line=cause.get("EndLine") or None,
                    provider=cause.get("Provider"),
                    service=cause.get("Service"),
                    primary_url=m.get("PrimaryURL"),
                    references=_refs(m.get("PrimaryURL"), m.get("References")),
                    remediation=m.get("Resolution") or "",
                )
            )

        for s in result.get("Secrets") or []:
            secrets.append(
                Secret(
                    rule_id=s.get("RuleID") or "UNKNOWN",
                    category=s.get("Category") or "",
                    title=s.get("Title") or "",
                    severity=_sev(s.get("Severity")),
                    target=target,
                    start_line=s.get("StartLine") or None,
                    end_line=s.get("EndLine") or None,
                    match=(s.get("Match") or "")[:300],
                    remediation=SECRET_REMEDIATION,
                )
            )

    vulns.sort(key=lambda x: (SEVERITY_ORDER[x.severity], -(x.cvss_score or 0), x.id))
    misconfigs.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.id))
    secrets.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.target, x.start_line or 0))

    return ParsedReport(
        os=os_str,
        vulnerabilities=vulns,
        misconfigurations=misconfigs,
        secrets=secrets,
        vuln_counts=_counts(vulns),
        misconfig_counts=_counts(misconfigs),
        secret_counts=_counts(secrets),
    )