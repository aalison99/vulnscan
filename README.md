# VulnScan

Self-hosted security scanning web app. Scan container images, Git repositories
and uploaded code archives for vulnerabilities, exposed secrets and
misconfigurations, using your own compiled `vulnscan` binary.

## Architecture

| Service           | Stack                                  | Role                                                          |
| ----------------- | -------------------------------------- | ------------------------------------------------------------- |
| `vulnscan-server` | `debian:bookworm-slim` + `vulnscan`    | Scanner server; downloads the vulnerability DB once, shared   |
| `backend`         | FastAPI, SQLAlchemy, SQLite            | REST API, runs `vulnscan` in client/server mode, stores scans |
| `frontend`        | React, TypeScript, Vite, Tailwind, Nginx | Dashboard UI; Nginx proxies `/api` to `backend:8000`        |

Only the frontend is published to the host. The scanner server and the backend
are reachable only on the internal Compose network.

## Prerequisites

- Docker with the Compose plugin
- Your compiled **Linux AMD64** `vulnscan` binary
- Internet access for the first run (DB, checks bundle, images)

## Setup

1. Put the binary in the project root and make it executable:

   ```bash
   chmod +x ./vulnscan
   ./vulnscan --version   # sanity check, on a Linux AMD64 host
   ```

2. Build and start everything:

   ```bash
   docker compose up --build
   ```

3. Open **http://localhost:8080**.

The first start takes a few minutes: `vulnscan-server` downloads the
vulnerability database, and `backend` waits until the server is healthy. The DB
is stored in the `vulnscan-cache` volume, so later starts are fast.

To use a different port: `VULNSCAN_UI_PORT=9090 docker compose up --build`.

## Project layout

```
vulnscan/
├── vulnscan                  # your binary (not committed)
├── docker-compose.yml
├── vulnscan-server/Dockerfile
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/                  # FastAPI app (main, routes, scanner, parser, ...)
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    └── src/                  # React app
```

## Configuration (backend environment)

| Variable                | Default                              | Description                              |
| ----------------------- | ------------------------------------ | ---------------------------------------- |
| `VULNSCAN_SERVER_URL`   | `http://vulnscan-server:4954`        | Scanner server used in client mode       |
| `DATABASE_URL`          | `sqlite+aiosqlite:////data/vulnscan.db` | Scan history database                 |
| `DATA_DIR`              | `/data`                              | Database, temp and upload directories    |
| `SCAN_TIMEOUT_SECONDS`  | `900`                                | Per-scan timeout                         |
| `MAX_UPLOAD_MB`         | `200`                                | Archive upload limit                     |
| `MAX_EXTRACTED_MB`      | `1024`                               | Extracted size limit (zip-bomb guard)    |
| `MAX_ARCHIVE_FILES`     | `50000`                              | Max entries per archive                  |
| `MAX_CONCURRENT_SCANS`  | `2`                                  | Scans running in parallel                |

If you raise `MAX_UPLOAD_MB`, also raise `client_max_body_size` in
`frontend/nginx.conf` and the limit in `frontend/src/pages/NewScan.tsx`.

## API

| Method   | Path                                  | Description                                    |
| -------- | ------------------------------------- | ---------------------------------------------- |
| `POST`   | `/api/scans`                          | Start an image or repo scan, returns `scan_id` |
| `POST`   | `/api/scans/upload`                   | Upload a `.zip` / `.tar.gz` and scan it        |
| `GET`    | `/api/scans`                          | List scans with status and severity counts     |
| `GET`    | `/api/scans/{id}`                     | Full normalized report                         |
| `DELETE` | `/api/scans/{id}`                     | Delete a scan                                  |
| `GET`    | `/api/scans/{id}/export?format=json\|csv` | Download the report                        |
| `GET`    | `/api/health`                         | Backend, scanner version, server connectivity  |

Interactive docs: http://localhost:8080/api/docs

Example:

```bash
curl -X POST http://localhost:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"scan_type":"image","target":"alpine:3.19"}'
```

## AWS misconfiguration scanning

The `aws` scan type checks an AWS account for misconfigurations and ranks findings by a context-aware risk score instead of raw severity. It is read-only and implemented in `backend/awsscan/`.

- 21 rules across IAM, S3, network, logging and encryption, each tagged with a CIS AWS Foundations Benchmark v3.0 control id. **The control ids have not been verified against the benchmark PDF.**
- Score = severity x exploitability x exposure x environment context. See [docs/scoring.md](docs/scoring.md).
- Checks that cannot be read (for example AccessDenied) are listed as "could not be assessed", never reported as passes.

Try it without AWS: choose **New Scan > AWS Account** and keep the profile `sample`, or run the CLI:

```bash
cd backend
python -m awsscan sample                      # built-in demo data
python -m awsscan scan --profile myprofile --regions ap-south-1 --out findings.json
```

Scan target for the API/UI: `sample`, `env` (server environment credentials) or a named profile, optionally `profile@region1,region2`. Credentials are read from the server only and are never stored. Give the scanning identity the AWS managed policies `SecurityAudit` and `ViewOnlyAccess` (read-only). Do not use a production account for testing.

Tests (no AWS needed, uses `moto`):

```bash
cd backend && pip install -r requirements-dev.txt && pytest
```

## Local frontend development

```bash
cd frontend
npm install
npm run dev     # http://localhost:5173, proxies /api to localhost:8000
```

Run `npm install` once and commit `package-lock.json` for reproducible builds.
You can then switch the frontend Dockerfile to `npm ci`.

## Scanning local Docker images

Remote images are pulled directly. To scan images from the host's Docker daemon,
uncomment the `/var/run/docker.sock` mount under `backend` in
`docker-compose.yml`. This gives the backend container visibility into the host's
Docker, so only enable it on trusted hosts.

## Troubleshooting

- **`vulnscan-server` is unhealthy.** Check `docker compose logs vulnscan-server`.
  The first boot needs network access to download the DB. If your rebrand changed
  the health route, change the healthcheck to `["CMD", "vulnscan", "--version"]`.
- **Build fails at `vulnscan --version`.** The binary is missing, not executable,
  not Linux AMD64, or needs a newer glibc than bookworm provides.
- **Scan fails with "unknown flag".** All CLI flags are built in `build_command()`
  in `backend/app/scanner.py`. Adjust them there if your rebrand differs.
- **Misconfiguration or secret scans fail offline.** The backend downloads the
  checks bundle on its first scan and caches it in the `vulnscan-backend-cache`
  volume.
- **Reset everything:** `docker compose down -v` (also deletes scan history).

## Security notes

- The scanner is always run with an argument list, never through a shell.
- Archive extraction blocks path traversal, skips symlinks and special files,
  and enforces size and entry limits.
- CSV exports neutralize spreadsheet formula injection.
- There is no authentication. Run VulnScan on a trusted network or put it behind
  a reverse proxy with auth. Repo scans fetch any `http(s)` URL the backend can
  reach, so restrict outbound access if you expose it more widely.