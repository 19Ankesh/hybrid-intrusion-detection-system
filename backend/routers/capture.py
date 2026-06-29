"""Capture control router — start, stop, status"""
from fastapi import APIRouter, Depends
from services.auth_service import require_admin, get_current_user
from services.capture_service import get_capture_status, stop_capture, start_capture
import asyncio

router = APIRouter()


@router.get("/status")
def capture_status(_: dict = Depends(get_current_user)):
    """Return live capture statistics. Accessible to all authenticated users."""
    return get_capture_status()


@router.post("/stop")
def capture_stop(_: dict = Depends(require_admin)):
    """Stop live packet capture. Admin only."""
    stop_capture()
    return {"message": "Capture stopped."}


@router.post("/start")
async def capture_start(_: dict = Depends(require_admin)):
    """(Re-)start live packet capture. Admin only."""
    loop = asyncio.get_event_loop()
    await start_capture(loop)
    return {"message": "Capture started."}
