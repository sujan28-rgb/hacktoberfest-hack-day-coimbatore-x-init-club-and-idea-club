"""Monitoring controls and notifications inherit the existing case authorization."""
from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sentinel_evidence.api.cases import current_case, store

router = APIRouter()


@router.get("/cases/{case_id}/monitor")
def status(request: Request, case_id: str = Depends(current_case)):
    return request.app.state.monitor.status(case_id)


@router.post("/cases/{case_id}/monitor/{action}")
def control(action: str, request: Request, case_id: str = Depends(current_case)):
    manager = request.app.state.monitor
    methods = {"start": manager.enable, "pause": manager.pause, "retry": manager.retry}
    if action not in methods:
        raise HTTPException(404, "Unknown monitoring action")
    try:
        return methods[action](case_id)
    except ValueError as error:
        raise HTTPException(400, str(error))


@router.get("/cases/{case_id}/notifications")
def notifications(case_id: str = Depends(current_case), page: int = Query(1, ge=1),
                  size: int = Query(30, ge=1, le=100), db=Depends(store)):
    return db.notifications(case_id, page, size)


@router.post("/cases/{case_id}/notifications/{notification_id}/read")
def mark_read(notification_id: str, case_id: str = Depends(current_case), db=Depends(store)):
    if not db.read_notification(case_id, notification_id):
        raise HTTPException(404, "Notification not found")
    return {"read": True}
