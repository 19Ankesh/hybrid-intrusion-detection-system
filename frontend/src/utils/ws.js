/**
 * WebSocket utility for the Hybrid IDS dashboard.
 * Manages a single persistent connection to /ws?token=<jwt>.
 * Auto-reconnects on disconnect with exponential back-off (max 30s).
 *
 * Usage:
 *   import { connectWS, disconnectWS, addWSListener, removeWSListener } from "./ws";
 *   connectWS(token);
 *   const id = addWSListener((msg) => { ... });
 *   return () => { removeWSListener(id); disconnectWS(); };
 */

const WS_BASE =
  (process.env.REACT_APP_API_URL || "http://localhost:8000")
    .replace(/^http/, "ws")     // http→ws, https→wss
    .replace(/\/$/, "");        // strip trailing slash

let _socket    = null;
let _token     = null;
let _retryMs   = 1000;          // start at 1s, doubles up to 30s
let _retryTimer= null;
let _listeners = {};            // { id: fn }
let _nextId    = 1;
let _intentional = false;       // set true when we deliberately close

function _dispatch(msg) {
  for (const fn of Object.values(_listeners)) {
    try { fn(msg); } catch (e) { /* ignore listener errors */ }
  }
}

function _connect() {
  if (_socket && (_socket.readyState === WebSocket.OPEN || _socket.readyState === WebSocket.CONNECTING)) return;

  const url = `${WS_BASE}/ws?token=${encodeURIComponent(_token || "")}`;
  _socket = new WebSocket(url);

  _socket.onopen = () => {
    console.log("[WS] Connected to", url);
    _retryMs = 1000;  // reset back-off
    _dispatch({ type: "_connected" });

    // keep-alive ping every 25s
    _socket._ping = setInterval(() => {
      if (_socket.readyState === WebSocket.OPEN) _socket.send("ping");
    }, 25000);
  };

  _socket.onmessage = (ev) => {
    if (ev.data === "pong") return;  // keep-alive reply
    try {
      _dispatch(JSON.parse(ev.data));
    } catch (e) {
      console.warn("[WS] Non-JSON message:", ev.data);
    }
  };

  _socket.onclose = (ev) => {
    clearInterval(_socket._ping);
    _dispatch({ type: "_disconnected", code: ev.code });
    if (!_intentional) {
      console.warn(`[WS] Disconnected (code=${ev.code}). Retrying in ${_retryMs}ms…`);
      _retryTimer = setTimeout(() => {
        _retryMs = Math.min(_retryMs * 2, 30000);
        _connect();
      }, _retryMs);
    }
  };

  _socket.onerror = (e) => {
    console.warn("[WS] Error:", e);
  };
}

export function connectWS(token) {
  _intentional = false;
  _token = token;
  clearTimeout(_retryTimer);
  _connect();
}

export function disconnectWS() {
  _intentional = true;
  clearTimeout(_retryTimer);
  if (_socket) {
    clearInterval(_socket._ping);
    _socket.close();
    _socket = null;
  }
}

export function addWSListener(fn) {
  const id = _nextId++;
  _listeners[id] = fn;
  return id;
}

export function removeWSListener(id) {
  delete _listeners[id];
}
