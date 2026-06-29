"""
Hybrid IDS — FastAPI Application Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s")

from database import engine, Base
from routers import auth, detection, data, explain, ws, capture
from services.capture_service import start_capture, stop_capture
from services.traffic_generator import start_traffic_gen, stop_traffic_gen

# ── Create tables on startup ───────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create DB tables
    Base.metadata.create_all(bind=engine)
    # Start real-time packet capture (Linux only; no-op when CAPTURE_ENABLED=false)
    loop = asyncio.get_event_loop()
    asyncio.create_task(start_capture(loop))
    # Start autonomous traffic generator (works on all platforms including Windows Docker)
    asyncio.create_task(start_traffic_gen(loop))
    yield
    # Graceful shutdown
    stop_capture()
    stop_traffic_gen()

app = FastAPI(
    title="Hybrid IDS API",
    description="Intrusion Detection System using XGBoost + Isolation Forest",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,      prefix="/auth",    tags=["Authentication"])
app.include_router(detection.router, prefix="/detect",  tags=["Detection"])
app.include_router(data.router,      prefix="/data",    tags=["Data"])
app.include_router(explain.router,   prefix="/explain", tags=["Explainability"])
app.include_router(capture.router,   prefix="/capture", tags=["Capture"])
app.include_router(ws.router,                           tags=["WebSocket"])

@app.get("/health")
def health():
    return {"status": "ok", "system": "Hybrid IDS v1.0"}
