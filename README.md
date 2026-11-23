# VulnScan: AWS Misconfiguration Risk Scanner

A self-hosted web app that scans an AWS account for misconfigurations and ranks
them by a **context-aware risk score** instead of raw severity. The same mistake
scores higher in production, exposed to the internet, with sensitive data, than
in a test environment.

It started as a scanner for container images, Git repositories and code archives
(see [Legacy scan types](#legacy-scan-types)). The AWS scanner is the main feature.

## Quick start

Requires Docker with the Compose plugin. No other files or binaries are needed.

```bash
docker compose up --build
```

Open **http://localhost:8080**, choose **New Scan > AWS Account**, keep the
profile `sample` and start the scan. `sample` uses built-in demo data, so no AWS
account is needed.

To use a different port: `VULNSCAN_UI_PORT=9090 docker compose up --build`.

## What it does

- Reads an AWS account **read-only** and checks **21 rules** across IAM, S3,
  network, logging and encryption. Each rule is tagged with a CIS AWS Foundations
  Benchmark v3.0 control id. **The control ids have not been verified against the
  benchmark PDF.**
- Scores every finding:
  `risk = 100 x base severity x exploitability x exposure x environment context`.
  See [docs/scoring.md](docs/scoring.md).
- Shows the findings in a dashboard: top risks, an exposure x environment matrix,
  a findings table with a **Context-aware / Flat severity** toggle, filters,
  remediation status, and a detail panel that explains each score.
- Lists checks that could not be read (for example AccessDenied) as
  "could not be assessed". These are never reported as passes.
- Compares two scans through the API (new, fixed, unchanged findings) and exports
  findings to CSV.

## Architecture

| Service    | Stack                                    | Role                                                         |
| ---------- | ---------------------------------------- | ------------------------------------------------------------ |
| `backend`  | FastAPI, SQLAlchemy, SQLite, boto3       | REST API, runs the `awsscan` engine, stores scans and findings |
| `frontend` | React, TypeScript, Vite, Tailwind, Nginx | Dashboard UI; Nginx proxies `/api` to `backend:8000`         |

Only the frontend is published to the host.

```
Dashboard (React)  ->  API (FastAPI)  ->  awsscan engine  ->  AWS account (read-only)
                            |                                  or built-in sample data
                         SQLite
```

The engine (`backend/awsscan/`) works in three steps:

1. **Inventory:** boto3 collects the account's configuration into one JSON structure.
2. **Rules:** each rule is a pure function over the inventory and returns findings.
3. **Scoring:** each finding gets a 0-100 risk score and a breakdown of its factors.

## Project layout

```
.
├── docker-compose.yml
├── docs/scoring.md            # scoring model
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── app/                   # FastAPI app (routes, aws_routes, scanner, models, ...)
│   ├── awsscan/               # AWS scan engine
│   │   ├── inventory.py       #   boto3 collector (read-only)
│   │   ├── rules/             #   iam, s3, network, trail, encryption
│   │   ├── scoring.py         #   risk model
│   │   ├── weights.yaml       #   scoring weights (editable)
│   │   ├── sample.py          #   built-in demo inventory
│   │   └── __main__.py        #   CLI
│   └── tests/
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── src/                   # React app (pages/AwsScanView.tsx is the AWS view)
└── vulnscan-server/           # legacy, unused by the Docker stack
```

## Scanning a real AWS account

The scan target is one of:

| Target                       | Meaning                                                   |
| ---------------------------- | --------------------------------------------------------- |
| `sample`                     | Built-in demo data, no AWS access                         |
| `env`                        | Credentials from the backend's environment variables      |
| `myprofile`                  | A named profile in the backend's AWS config               |
| `myprofile@ap-south-1,us-east-1` | A named profile, limited to the listed regions        |

With no regions listed, all enabled regions are scanned.

Steps:

1. Create a **dedicated sandbox account or a read-only role**. Do not test on a
   production account.
2. Give the scanning identity the AWS managed policies `SecurityAudit` and
   `ViewOnlyAccess`. The scanner makes no write calls.
3. In `docker-compose.yml`, uncomment the read-only `~/.aws` mount under
   `backend`, then start a scan with your profile name.

Credentials are read by the backend only. They are never stored in the database
or written to logs, and they never pass through the browser.

### Command line

The engine also runs without the web app:

```bash
cd backend
python -m awsscan sample                       # built-in demo data
python -m awsscan scan --profile myprofile --regions ap-south-1 --out findings.json
```

### Rules

| Group      | Rules                                                                                                                                              |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| IAM (8)    | root access key; root without MFA; password length under 14; console user without MFA; credentials unused 45+ days; key older than 90 days; direct user policy; full `*:*` admin policy |
| S3 (4)     | public bucket; Block Public Access not fully on; no default encryption; plain HTTP allowed                                                         |
| Network (4)| SSH/RDP open to the internet; database port open to the internet; default security group has rules; public RDS instance                            |
| Logging (2)| no multi-region CloudTrail; log file validation off                                                                                                |
| Encryption (3) | EBS default encryption off; RDS storage unencrypted; KMS key rotation off                                                                      |

## API

| Method  | Path                                    | Description                                                        |
| ------- | --------------------------------------- | ------------------------------------------------------------------ |
| `POST`  | `/api/scans`                            | Start a scan. For AWS: `{"scan_type":"aws","target":"sample"}`     |
| `GET`   | `/api/scans`                            | List scans with status and counts                                  |
| `GET`   | `/api/scans/{id}`                       | Scan summary. For `aws`, counts are risk buckets                   |
| `DELETE`| `/api/scans/{id}`                       | Delete a scan and its findings                                     |
| `GET`   | `/api/scans/{id}/findings`              | AWS findings. Filters: `category`, `environment`, `exposure`, `status`, `min_risk`. `sort=risk` (context-aware) or `sort=severity` (flat) |
| `GET`   | `/api/scans/{id}/aws-report`            | Totals and the "could not be assessed" list                        |
| `PATCH` | `/api/findings/{id}`                    | Set status: `open`, `acknowledged`, `fixed`, `accepted-risk`       |
| `GET`   | `/api/scans/{a}/diff/{b}`               | New, fixed and unchanged findings between scan `a` and scan `b`    |
| `GET`   | `/api/scans/{id}/findings/export`       | Download findings as CSV                                           |
| `GET`   | `/api/health`                           | Backend health (scanner status is "degraded" without the legacy binary) |

Interactive docs: http://localhost:8080/api/docs

```bash
curl -X POST http://localhost:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"scan_type":"aws","target":"sample"}'
```

## Configuration (backend environment)

| Variable                | Default                                 | Description                           |
| ----------------------- | --------------------------------------- | ------------------------------------- |
| `DATABASE_URL`          | `sqlite+aiosqlite:////data/vulnscan.db` | Scan history database                 |
| `DATA_DIR`              | `/data`                                 | Database, temp and upload directories |
| `MAX_CONCURRENT_SCANS`  | `2`                                     | Scans running in parallel             |
| `SCAN_TIMEOUT_SECONDS`  | `900`                                   | Timeout for legacy scans              |

Scoring weights are in `backend/awsscan/weights.yaml`. Edit them and rebuild to
change multipliers and risk-bucket thresholds.

## Development

Tests need no AWS account; they use `moto` to mock AWS.

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

Run the backend and frontend without Docker:

```bash
# terminal 1
cd backend && pip install -r requirements.txt
DATA_DIR=./data DATABASE_URL=sqlite+aiosqlite:///./data/vulnscan.db \
  uvicorn app.main:app --port 8000

# terminal 2
cd frontend && npm install
npm run dev        # http://localhost:5173, proxies /api to localhost:8000
```

## Legacy scan types

The original app also scans container images, Git repositories and uploaded
archives (`image`, `repo`, `fs`; `POST /api/scans/upload`). These call an external
compiled **Linux AMD64** `vulnscan` binary and a `vulnscan-server`, which the
Docker stack **no longer includes**. In the Docker stack these scan types fail and
`/api/health` reports "degraded". They work only if you run the backend yourself
with `SCANNER_BIN` pointing at the binary and `VULNSCAN_SERVER_URL` at a running
scanner server. Their command flags are built in `build_command()` in
`backend/app/scanner.py`.

## Troubleshooting

- **`Could not authenticate to AWS`.** The `env` credentials or the profile are
  missing or invalid. For a profile, check the `~/.aws` mount is enabled.
- **`AWS profile '...' not found on the server`.** The profile name is not in the
  backend container's AWS config.
- **Findings list "could not be assessed".** The identity lacks a read permission.
  Add `SecurityAudit` and `ViewOnlyAccess` and scan again.
- **Everything is "low" risk.** The default thresholds (critical 70, high 50,
  medium 30) are untuned. Adjust `weights.yaml`.
- **Reset everything:** `docker compose down -v` (also deletes scan history).

## Limitations

- The CIS control ids are unverified, and results have not been compared with
  Prowler or tested on a seeded real AWS account.
- Scoring multipliers are chosen by judgement, not fitted to data. Exposure is
  taken from each resource's own configuration; routes and network ACLs are not
  traced. Environment context depends on resource tags.
- There is no attack-path analysis and no screen for scan diffs yet (the API
  exists).

## Security notes

- The scanner makes no write calls to AWS and never stores or logs credentials.
- AWS scan targets are validated against a strict pattern.
- CSV exports neutralize spreadsheet formula injection.
- There is no authentication. Run it on a trusted machine or network, or behind a
  reverse proxy with auth.
