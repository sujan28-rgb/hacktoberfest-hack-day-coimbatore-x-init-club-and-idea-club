import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel
from sentinel_evidence.api.models import ApiClaim, ApiEvent, ApiFinding, ApiSource
from sentinel_evidence.mocks.services import EvidenceService, AIService, get_evidence_service, get_ai_service

router = APIRouter()

# Simple mock auth/isolation check
def get_current_case(case_id: str):
    # In a real app, this would check user authorization for the specific case
    if case_id not in ["case-1"]:
        raise HTTPException(status_code=403, detail="Not authorized or case not found")
    return case_id

class PaginatedEvents(BaseModel):
    items: List[ApiEvent]
    total: int
    page: int
    size: int

class PaginatedClaims(BaseModel):
    items: List[ApiClaim]
    total: int
    page: int
    size: int

class PaginatedFindings(BaseModel):
    items: List[ApiFinding]
    total: int
    page: int
    size: int

@router.post("/cases/{case_id}/import")
async def import_evidence(
    case_id: str = Depends(get_current_case),
    file: UploadFile = File(...),
):
    # Security: File type validation
    if not file.filename.endswith(".jsonl"):
        raise HTTPException(status_code=400, detail="Only JSONL files are supported")

    # Security: Path traversal prevention
    filename = os.path.basename(file.filename)
    if not filename.endswith(".jsonl"):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Security: Size limit (mocking reading up to a limit)
    MAX_SIZE = 10 * 1024 * 1024 # 10MB
    contents = await file.read()
    if len(contents) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large")

    return {"status": "success", "filename": filename, "size": len(contents), "hash_status": "mock_hash_verified"}

@router.get("/cases/{case_id}/sources", response_model=List[ApiSource])
def get_sources(case_id: str = Depends(get_current_case), service: EvidenceService = Depends(get_evidence_service)):
    return service.get_sources(case_id)

@router.get("/cases/{case_id}/events", response_model=PaginatedEvents)
def get_events(
    case_id: str = Depends(get_current_case),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    service: EvidenceService = Depends(get_evidence_service)
):
    events = service.get_events(case_id)
    start = (page - 1) * size
    end = start + size
    return {"items": events[start:end], "total": len(events), "page": page, "size": size}

@router.get("/cases/{case_id}/events/{event_id}", response_model=ApiEvent)
def get_event(
    event_id: str,
    case_id: str = Depends(get_current_case),
    service: EvidenceService = Depends(get_evidence_service)
):
    event = service.get_event(case_id, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

@router.get("/cases/{case_id}/claims", response_model=PaginatedClaims)
def get_claims(
    case_id: str = Depends(get_current_case),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    service: EvidenceService = Depends(get_evidence_service)
):
    claims = service.get_claims(case_id)
    start = (page - 1) * size
    end = start + size
    return {"items": claims[start:end], "total": len(claims), "page": page, "size": size}

@router.get("/cases/{case_id}/claims/{claim_id}/explain")
def explain_claim(
    claim_id: str,
    case_id: str = Depends(get_current_case),
    ai_service: AIService = Depends(get_ai_service)
):
    # This is a mock explanation, distinct from facts
    explanation = ai_service.get_explanation(case_id, claim_id)
    return {
        "explanation": explanation["explanation"],
        "status": explanation["status"],
        "disclaimer": "This is an AI-generated explanation and may contain errors. Do not treat as deterministic fact."
    }

@router.get("/cases/{case_id}/findings", response_model=PaginatedFindings)
def get_findings(
    case_id: str = Depends(get_current_case),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    service: EvidenceService = Depends(get_evidence_service)
):
    findings = service.get_findings(case_id)
    start = (page - 1) * size
    end = start + size
    return {"items": findings[start:end], "total": len(findings), "page": page, "size": size}
