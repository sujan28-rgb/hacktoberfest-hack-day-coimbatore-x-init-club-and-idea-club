from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
from sentinel_evidence.db.cases import CaseStore
from sentinel_evidence.monitoring.service import MonitorManager
from sentinel_evidence.api.cases import router as cases_router
from sentinel_evidence.api.monitoring import router as monitoring_router


@asynccontextmanager
async def lifespan(app):
    app.state.case_store = CaseStore(os.getenv("SENTINEL_DB", ".sentinel/cases.db"))
    try:
        interval = int(os.getenv("SENTINEL_MONITOR_INTERVAL", "5"))
    except ValueError:
        interval = 5
    manager = MonitorManager(app.state.case_store, os.getenv("SENTINEL_EVIDENCE_WORKSPACE"), interval)
    app.state.monitor = manager
    manager.start()
    try:
        yield
    finally:
        manager.stop()


app = FastAPI(title="Sentinel Evidence API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Safe error handling to prevent leaking internals
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred."}
    )

app.include_router(monitoring_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")

@app.get("/health")
def health():
    return {"status": "ok"}
