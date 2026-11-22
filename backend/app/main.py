import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import settings
from .database import engine, init_db
from .routes import router
from .scanner import recover_stale_scans, shutdown_tasks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.ensure_dirs()
    await init_db()
    await recover_stale_scans()
    yield
    await shutdown_tasks()
    await engine.dispose()


app = FastAPI(
    title="VulnScan API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.include_router(router)