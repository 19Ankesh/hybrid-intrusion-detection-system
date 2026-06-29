"""
WebSocket router — real-time alert broadcast to all connected dashboards.
Each dashboard connects once, receives 'new_alert' events instantly.
JWT token is passed as a query param for authentication.
"""
import json
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

router = APIRouter()


class ConnectionManager:
    """Manages all active WebSocket connections and broadcasts to them."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send a JSON message to every connected dashboard. Dead sockets are removed."""
        dead = []
        payload = json.dumps(message, default=str)
        for ws in self.active_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


# Singleton shared across all routers
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(default="")):
    """
    WebSocket endpoint for real-time alert streaming.
    Clients must pass a valid JWT as ?token=<jwt>.
    Messages sent by client:
      "ping"  → server replies "pong"  (keep-alive)
    Messages pushed by server:
      { "type": "new_alert",  "payload": AlertOut }
      { "type": "stats_delta","payload": {counter deltas} }
    """
    from services.auth_service import decode_token

    # Authenticate before accepting
    try:
        if not token:
            raise ValueError("Missing token")
        decode_token(token)          # raises HTTPException on invalid token
    except Exception:
        await websocket.close(code=4001)        # 4001 = Unauthorized
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
