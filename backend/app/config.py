import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    scanner_bin: str = os.getenv("SCANNER_BIN", "vulnscan")
    server_url: str = os.getenv(
        "VULNSCAN_SERVER_URL", "http://vulnscan-server:4954"
    ).rstrip("/")
    database_url: str = os.getenv(
        "DATABASE_URL", "sqlite+aiosqlite:////data/vulnscan.db"
    )
    data_dir: Path = Path(os.getenv("DATA_DIR", "/data"))

    scan_timeout_seconds: int = _env_int("SCAN_TIMEOUT_SECONDS", 900)
    max_upload_mb: int = _env_int("MAX_UPLOAD_MB", 200)
    max_extracted_mb: int = _env_int("MAX_EXTRACTED_MB", 1024)
    max_archive_files: int = _env_int("MAX_ARCHIVE_FILES", 50000)
    max_concurrent_scans: int = _env_int("MAX_CONCURRENT_SCANS", 2)

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.tmp_dir, self.upload_dir):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()