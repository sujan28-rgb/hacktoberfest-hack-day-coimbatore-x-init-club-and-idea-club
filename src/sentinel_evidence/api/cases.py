"""Case-scoped API over the shared deterministic engine."""
import os
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Header, Response
from fastapi.concurrency import run_in_threadpool
from sentinel_evidence.db.cases import CaseStore
from sentinel_evidence.pipeline import analyze, MAX_BYTES
from sentinel_evidence.explain.packet import build_packet
from sentinel_evidence.explain.ollama import explain

router = APIRouter()


def store():
    return CaseStore(os.getenv("SENTINEL_DB", ".sentinel/cases.db"))


def current_case(case_id: str, authorization: str = Header(default=""), db=Depends(store)):
    token = authorization.removeprefix("Bearer ")
    if not authorization.startswith("Bearer ") or not db.authorized(case_id, token):
        raise HTTPException(404, "Case not found")
    return case_id


@router.post("/cases", status_code=201)
def create_case(db=Depends(store)):
    return db.create()


@router.post("/cases/{case_id}/import")
async def import_evidence(case_id: str = Depends(current_case), file: UploadFile = File(...), db=Depends(store)):
    filename = file.filename or ""
    if not filename.lower().endswith(".jsonl") or any(c in filename for c in ("/", "\\", "\x00")) or filename in {".", ".."} or len(filename) > 200:
        raise HTTPException(400, "Provide a safe JSONL filename")
    contents = await file.read(MAX_BYTES + 1)
    await file.close()
    if len(contents) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 10 MiB")
    try:
        report = await run_in_threadpool(analyze, contents, filename)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    await run_in_threadpool(db.save, case_id, report, contents)
    return {"status": "success", "filename": filename, "size": len(contents),
            "hash_status": "sha256_verified", "run": report["run"]}


def event_view(event):
    raw = event["raw_fields"]
    return {**event, "source_id": event["source"]["file_hash"],
            "source_locator": f'line:{event["source"]["line_number"]}',
            "normalized_timestamp": event["timestamp"] or "",
            "provider": str(raw.get("Provider", "")), "channel": str(raw.get("Channel", "")),
            "event_record_id": str(raw.get("EventRecordID", ""))}


def claim_view(claim, report):
    events = {e["event_id"]: e for e in report["events"]}
    # Preserve complete canonical support sets separately from presentation drill-down.
    supports = []
    for support in claim["support_sets"]:
        for ref in support["evidence_ids"]:
            if ref in events:
                supports.append({"event_id": ref, "fields": list(events[ref]["raw_fields"])})
    return {**claim, "canonical_support_sets": claim["support_sets"],
            "canonical_bound_entities": claim["bound_entities"],
            "canonical_contradictory_evidence": claim["contradictory_evidence"],
            "bound_entities": [f"{k}: {v}" for k, v in claim["bound_entities"].items()],
            "support_sets": supports,
            "contradictory_evidence": [ref for s in claim["contradictory_evidence"] for ref in s["evidence_ids"]]}


@router.get("/cases/{case_id}/sources")
def sources(case_id: str = Depends(current_case), db=Depends(store)):
    return db.report(case_id)["sources"]


@router.get("/cases/{case_id}/sources/{source_id}/original")
def original(source_id: str, case_id: str = Depends(current_case), db=Depends(store)):
    contents = db.original(case_id, source_id)
    if contents is None:
        raise HTTPException(404, "Source not found")
    return Response(contents, media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="evidence.jsonl"',
                             "X-Content-Type-Options": "nosniff"})


@router.get("/cases/{case_id}/report")
def report(case_id: str = Depends(current_case), db=Depends(store)):
    return db.report(case_id)


@router.get("/cases/{case_id}/events/{event_id}")
def event(event_id: str, case_id: str = Depends(current_case), db=Depends(store)):
    record = next((e for e in db.report(case_id)["events"] if e["event_id"] == event_id), None)
    if record is None:
        raise HTTPException(404, "Event not found")
    return event_view(record)


@router.get("/cases/{case_id}/claims/{claim_id}/packet")
def packet(claim_id: str, case_id: str = Depends(current_case), db=Depends(store)):
    try:
        return build_packet(db.report(case_id), claim_id)
    except KeyError:
        raise HTTPException(404, "Claim not found")
    except ValueError as error:
        raise HTTPException(413, str(error))


@router.get("/cases/{case_id}/claims/{claim_id}/explain")
def explanation(claim_id: str, case_id: str = Depends(current_case), db=Depends(store)):
    try:
        return explain(db.report(case_id), claim_id)
    except KeyError:
        raise HTTPException(404, "Claim not found")


@router.get("/cases/{case_id}/{collection}")
def collection(collection: str, case_id: str = Depends(current_case),
               page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=100), db=Depends(store)):
    if collection not in {"events", "claims", "findings", "edges"}:
        raise HTTPException(404, "Collection not found")
    report = db.report(case_id)
    records = report[collection]
    selected = records[(page - 1) * size:page * size]
    if collection == "events":
        selected = [event_view(e) for e in selected]
    elif collection == "claims":
        selected = [claim_view(c, report) for c in selected]
    elif collection == "findings":
        selected = [{**f, "detector": "sentinel-baseline", "detector_version": "1",
                     "rule_id": f["rule_name"], "source_event_refs": f["matched_event_ids"],
                     "original_severity": f["severity"], "matched_fields": {}, "mapping_status": "linked"}
                    for f in selected]
    return {"items": selected, "total": len(records), "page": page, "size": size}
