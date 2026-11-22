import asyncio

import httpx
import pytest
import pytest_asyncio

from app.main import app


@pytest_asyncio.fixture
async def client():
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            yield c


async def run_scan(client, target="sample"):
    r = await client.post("/api/scans", json={"scan_type": "aws", "target": target})
    assert r.status_code == 202, r.text
    sid = r.json()["scan_id"]
    for _ in range(100):
        s = (await client.get(f"/api/scans/{sid}")).json()
        if s["status"] in ("completed", "failed"):
            return s
        await asyncio.sleep(0.05)
    raise AssertionError("scan did not finish")


@pytest.mark.asyncio
async def test_aws_scan_persists_scored_findings(client):
    s = await run_scan(client)
    assert s["status"] == "completed", s
    assert s["scan_type"] == "aws"
    assert s["misconfig_count"] > 10
    assert s["severity_counts"]["critical"] >= 1  # risk buckets feed the existing KPI cards
    rows = (await client.get(f"/api/scans/{s['id']}/findings")).json()
    assert len(rows) == s["misconfig_count"]
    assert rows == sorted(rows, key=lambda r: r["risk_score"], reverse=True)
    assert set(rows[0]["breakdown"]) == {"base", "exploitability", "exposure", "context", "final"}


@pytest.mark.asyncio
async def test_flat_vs_contextual_ordering_differs(client):
    s = await run_scan(client)
    ctx = (await client.get(f"/api/scans/{s['id']}/findings?sort=risk")).json()
    flat = (await client.get(f"/api/scans/{s['id']}/findings?sort=severity")).json()
    assert [r["id"] for r in ctx] != [r["id"] for r in flat]
    bases = [r["base_severity"] for r in flat]
    assert bases == sorted(bases, reverse=True)


@pytest.mark.asyncio
async def test_filters(client):
    s = await run_scan(client)
    sid = s["id"]
    only_s3 = (await client.get(f"/api/scans/{sid}/findings?category=s3")).json()
    assert only_s3 and all(r["category"] == "s3" for r in only_s3)
    test_env = (await client.get(f"/api/scans/{sid}/findings?environment=test")).json()
    assert test_env and all(r["environment"] == "test" for r in test_env)
    high = (await client.get(f"/api/scans/{sid}/findings?min_risk=70")).json()
    assert high and all(r["risk_score"] >= 70 for r in high)
    assert (await client.get(f"/api/scans/{sid}/findings?status=bogus")).status_code == 422


@pytest.mark.asyncio
async def test_status_update_and_diff(client):
    a = await run_scan(client)
    b = await run_scan(client)
    rows = (await client.get(f"/api/scans/{a['id']}/findings")).json()
    r = await client.patch(f"/api/findings/{rows[0]['id']}", json={"status": "acknowledged"})
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert (await client.patch(f"/api/findings/{rows[0]['id']}", json={"status": "nope"})).status_code == 422
    assert (await client.patch("/api/findings/missing", json={"status": "fixed"})).status_code == 404
    d = (await client.get(f"/api/scans/{a['id']}/diff/{b['id']}")).json()
    assert d["new"] == [] and d["fixed"] == [] and len(d["unchanged"]) == len(rows)


@pytest.mark.asyncio
async def test_export_csv_and_not_assessed(client):
    s = await run_scan(client)
    r = await client.get(f"/api/scans/{s['id']}/findings/export")
    assert r.status_code == 200 and r.text.startswith("risk_score,")
    rep = (await client.get(f"/api/scans/{s['id']}/aws-report")).json()
    assert rep["not_assessed"] and rep["summary"]["total"] == s["misconfig_count"]
    assert (await client.get(f"/api/scans/{s['id']}/export?format=csv")).status_code == 409


@pytest.mark.asyncio
async def test_delete_removes_findings(client):
    s = await run_scan(client)
    assert (await client.delete(f"/api/scans/{s['id']}")).status_code == 204
    assert (await client.get(f"/api/scans/{s['id']}/findings")).status_code == 404


@pytest.mark.asyncio
async def test_validation_and_missing_credentials(client):
    bad = await client.post("/api/scans", json={"scan_type": "aws", "target": "bad target; rm -rf /"})
    assert bad.status_code == 422
    s = await run_scan(client, "no-such-profile")
    assert s["status"] == "failed" and "not found" in s["error"]


@pytest.mark.asyncio
async def test_existing_scan_types_still_validate(client):
    assert (await client.post("/api/scans", json={"scan_type": "image", "target": "alpine:3.19"})).status_code == 202
    assert (await client.post("/api/scans", json={"scan_type": "repo", "target": "ftp://x"})).status_code == 422
    assert (await client.get("/api/scans")).status_code == 200
