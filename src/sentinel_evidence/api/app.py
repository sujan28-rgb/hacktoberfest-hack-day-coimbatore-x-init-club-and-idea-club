from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sentinel_evidence.api.cases import router as cases_router

app = FastAPI(title="Sentinel Evidence API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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

app.include_router(cases_router, prefix="/api/v1")
