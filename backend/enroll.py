"""
Endpoint onboarding: enrollment tokens, the one-line installer, live install progress,
per-agent keys and remote uninstall.

    laptop:  irm http://<console>:8000/install.ps1?t=<token> | iex

    or, from the public download page (no address, no token):
    setup.ps1 ── UDP broadcast :47800 / subnet scan ─▶ GET /api/discover   (finds this console)
              ── POST /api/enroll/request ──────────▶ join request, shown on the dashboard
              ◀─ approved (by an analyst, or auto-approve) ── token ─▶ runs install.ps1 as above
    install.ps1 ── POST /api/enroll/progress ──▶ installs table ──▶ {"type":"install"} on /ws
                ── POST /api/enroll ───────────▶ agent id + agent key (written to config.json)
    agent     ── first heartbeat ─────────────▶ step "online"
              ── first ingest ────────────────▶ step "telemetry"  (status "protected")
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel

from normalize import now_iso

HERE = Path(__file__).parent
AGENT_DIR = HERE.parent / "agent"
PAYLOAD = HERE / "payload"
LEGACY_TOKEN = os.environ.get("AEGIS_TOKEN", "hackathon-demo-token")

STEPS = [
    ("connect", "Reached the console"),
    ("runtime", "Agent runtime installed"),
    ("enroll", "Endpoint enrolled"),
    ("sysmon", "Sysmon telemetry"),
    ("audit", "Audit and script logging"),
    ("service", "Agent service started"),
    ("online", "First heartbeat"),
    ("telemetry", "First events received"),
]
STEP_IDS = [s for s, _ in STEPS]

PAYLOAD_FILES = {
    "python-embed-amd64.zip": PAYLOAD / "python-embed-amd64.zip",
    "python-embed-arm64.zip": PAYLOAD / "python-embed-arm64.zip",
    "Sysmon.zip": PAYLOAD / "Sysmon.zip",
    "sysmonconfig.xml": PAYLOAD / "sysmonconfig.xml",
    "agent.py": AGENT_DIR / "agent.py",
    "uninstall.ps1": AGENT_DIR / "setup" / "uninstall.ps1",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS installs (
  id TEXT PRIMARY KEY, hostname TEXT, user TEXT, os TEXT, arch TEXT, ip TEXT,
  agent_id TEXT, status TEXT, steps TEXT, started_at TEXT, updated_at TEXT
);
"""


def _install_row(r) -> Dict[str, Any]:
    d = dict(r)
    d["steps"] = json.loads(d["steps"] or "{}")
    return d


DISCOVERY_PORT = 47800
REQUEST_TTL = 600  # seconds a join request waits for a decision


class Enrollment:
    def __init__(self, db):
        self.db = db
        self.requests: Dict[str, Dict[str, Any]] = {}  # join requests from setup.ps1, by id (in memory)
        with db.lock, db.conn:
            db.conn.executescript(SCHEMA)
            cols = {r[1] for r in db.conn.execute("PRAGMA table_info(agents)")}
            if "agent_key" not in cols:
                db.conn.execute("ALTER TABLE agents ADD COLUMN agent_key TEXT")
            if "install_id" not in cols:
                db.conn.execute("ALTER TABLE agents ADD COLUMN install_id TEXT")
            row = db.conn.execute("SELECT value FROM settings WHERE key='enroll_token'").fetchone()
            if not row:
                db.conn.execute("INSERT INTO settings VALUES ('enroll_token', ?)", (self._new_token(),))
            self.keys: Dict[str, str] = {
                k: a for k, a in db.conn.execute("SELECT agent_key, id FROM agents WHERE agent_key IS NOT NULL")}
            # agents still waiting for their first heartbeat / first events
            self.awaiting: Dict[str, str] = {
                r["agent_id"]: r["id"] for r in db.conn.execute(
                    "SELECT id, agent_id FROM installs WHERE agent_id IS NOT NULL AND status IN ('installing','online')")}

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(9)

    # ------------------------------------------------------------- tokens
    @property
    def token(self) -> str:
        with self.db.lock:
            return self.db.conn.execute("SELECT value FROM settings WHERE key='enroll_token'").fetchone()[0]

    def rotate(self) -> str:
        t = self._new_token()
        with self.db.lock, self.db.conn:
            self.db.conn.execute("UPDATE settings SET value=? WHERE key='enroll_token'", (t,))
        return t

    def check_enroll(self, token: Optional[str]) -> None:
        if not token or not secrets.compare_digest(token, self.token):
            raise HTTPException(401, "enrollment token is not valid; copy a fresh install command from the console")

    def check_agent(self, token: Optional[str], agent_id: Optional[str] = None) -> None:
        """Legacy shared token (lab VM running agent.py by hand) or this agent's own key."""
        if token == LEGACY_TOKEN:
            return
        owner = self.keys.get(token or "")
        if not owner or (agent_id and owner != agent_id):
            raise HTTPException(401, "bad agent key")

    # ------------------------------------------------------------- installs
    def get(self, install_id: str) -> Optional[Dict[str, Any]]:
        with self.db.lock:
            r = self.db.conn.execute("SELECT * FROM installs WHERE id=?", (install_id,)).fetchone()
        return _install_row(r) if r else None

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.db.lock:
            rows = self.db.conn.execute("SELECT * FROM installs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [_install_row(r) for r in rows]

    def progress(self, body: Dict[str, Any], ip: Optional[str]) -> Dict[str, Any]:
        iid = body["install_id"]
        step, state = body.get("step"), body.get("state")
        now = now_iso()
        cur = self.get(iid)
        steps = cur["steps"] if cur else {}
        if step in STEP_IDS and state in ("active", "done", "fail", "skip"):
            prev = steps.get(step, {})
            steps[step] = {"state": state, "detail": body.get("detail") or prev.get("detail") or "",
                           "started": prev.get("started") or now, "at": now}
        status = cur["status"] if cur else "installing"
        if state == "fail":
            status = "failed"
        with self.db.lock, self.db.conn:
            if cur:
                self.db.conn.execute(
                    "UPDATE installs SET steps=?, status=?, updated_at=?, hostname=COALESCE(?,hostname), "
                    "user=COALESCE(?,user), os=COALESCE(?,os), arch=COALESCE(?,arch) WHERE id=?",
                    (json.dumps(steps), status, now, body.get("hostname"), body.get("user"), body.get("os"),
                     body.get("arch"), iid))
            else:
                self.db.conn.execute(
                    "INSERT INTO installs (id, hostname, user, os, arch, ip, status, steps, started_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (iid, body.get("hostname"), body.get("user"), body.get("os"), body.get("arch"), ip,
                     status, json.dumps(steps), now, now))
        return self.get(iid)

    def _mark(self, install_id: str, step: str, detail: str, status: str) -> Optional[Dict[str, Any]]:
        cur = self.get(install_id)
        if not cur:
            return None
        now = now_iso()
        cur["steps"][step] = {"state": "done", "detail": detail, "started": now, "at": now}
        with self.db.lock, self.db.conn:
            self.db.conn.execute("UPDATE installs SET steps=?, status=?, updated_at=? WHERE id=?",
                                 (json.dumps(cur["steps"]), status, now, install_id))
        return self.get(install_id)

    def enroll(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Issue (or re-issue, on reinstall) an agent id and a fresh key."""
        agent_id = body.get("agent_id") or str(uuid.uuid4())
        key = secrets.token_urlsafe(24)
        now = now_iso()
        with self.db.lock, self.db.conn:
            old = self.db.conn.execute("SELECT agent_key FROM agents WHERE id=?", (agent_id,)).fetchone()
            self.db.conn.execute(
                "INSERT INTO agents (id, hostname, first_seen, last_seen, is_admin, info, agent_key, install_id) "
                "VALUES (?,?,?,NULL,1,'{}',?,?) ON CONFLICT(id) DO UPDATE SET agent_key=excluded.agent_key, "
                "install_id=excluded.install_id, hostname=excluded.hostname",
                (agent_id, body.get("hostname"), now, key, body["install_id"]))
            self.db.conn.execute("UPDATE installs SET agent_id=? WHERE id=?", (agent_id, body["install_id"]))
        if old and old[0]:
            self.keys.pop(old[0], None)
        self.keys[key] = agent_id
        self.awaiting[agent_id] = body["install_id"]
        return {"agent_id": agent_id, "key": key}

    def on_heartbeat(self, agent_id: str, info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        iid = self.awaiting.get(agent_id)
        if not iid:
            return None
        cur = self.get(iid)
        if not cur or cur["steps"].get("online", {}).get("state") == "done":
            return None
        chans = len(info.get("channels") or [])
        return self._mark(iid, "online", f"agent v{info.get('agent_version')}, {chans} event logs", "online")

    def on_ingest(self, agent_id: str, count: int) -> Optional[Dict[str, Any]]:
        iid = self.awaiting.pop(agent_id, None)
        if not iid:
            return None
        cur = self.get(iid)
        if cur and cur["steps"].get("online", {}).get("state") != "done":
            self._mark(iid, "online", "", "online")
        return self._mark(iid, "telemetry", f"{count} event{'s' if count != 1 else ''} in the first batch", "protected")

    # ------------------------------------------------------------- join requests
    @property
    def auto_approve(self) -> bool:
        with self.db.lock:
            r = self.db.conn.execute("SELECT value FROM settings WHERE key='auto_approve'").fetchone()
        return bool(r and r[0] == "1")

    def set_auto_approve(self, on: bool) -> None:
        with self.db.lock, self.db.conn:
            self.db.conn.execute("INSERT OR REPLACE INTO settings VALUES ('auto_approve', ?)", ("1" if on else "0",))

    def _expire(self) -> None:
        now = time.time()
        for rid, r in list(self.requests.items()):
            if now - r["_t"] > REQUEST_TTL * (3 if r["status"] != "pending" else 1):
                del self.requests[rid]

    def pending(self) -> List[Dict[str, Any]]:
        self._expire()
        return [self.public_request(r) for r in self.requests.values() if r["status"] == "pending"]

    @staticmethod
    def public_request(r: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in r.items() if not k.startswith("_")}

    def new_request(self, body: Dict[str, Any], ip: Optional[str]) -> Dict[str, Any]:
        self._expire()
        if sum(r["status"] == "pending" for r in self.requests.values()) >= 25:
            raise HTTPException(429, "too many machines are waiting for approval; try again shortly")
        rid = secrets.token_urlsafe(12)
        r = {"id": rid, "hostname": (body.get("hostname") or "")[:64], "user": (body.get("user") or "")[:96],
             "os": (body.get("os") or "")[:96], "arch": (body.get("arch") or "")[:16], "ip": ip,
             "status": "pending", "created_at": now_iso(), "decided_at": None, "_t": time.time()}
        self.requests[rid] = r
        if self.auto_approve:
            self.decide(rid, True)
        return r

    def decide(self, rid: str, approve: bool) -> Optional[Dict[str, Any]]:
        r = self.requests.get(rid)
        if not r or r["status"] != "pending":
            return None
        r["status"] = "approved" if approve else "denied"
        r["decided_at"] = now_iso()
        return r

    def remove_agent(self, agent_id: str) -> None:
        with self.db.lock, self.db.conn:
            row = self.db.conn.execute("SELECT agent_key, install_id FROM agents WHERE id=?", (agent_id,)).fetchone()
            self.db.conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
            self.db.conn.execute("UPDATE commands SET status='expired' WHERE agent_id=? AND status='pending'", (agent_id,))
            if row and row["install_id"]:
                self.db.conn.execute("UPDATE installs SET status='removed', updated_at=? WHERE id=?",
                                     (now_iso(), row["install_id"]))
        if row and row["agent_key"]:
            self.keys.pop(row["agent_key"], None)
        self.awaiting.pop(agent_id, None)


# ------------------------------------------------------------------ console addresses
def lan_addresses(port: int) -> List[Dict[str, str]]:
    """Addresses a laptop on the same network could use to reach this console."""
    found: List[Dict[str, str]] = []
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
        iface = ""
        for line in out.splitlines():
            m = re.match(r"^(\S+?):? ", line)
            if m and not line.startswith(("\t", " ")):
                iface = m.group(1).rstrip(":")
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m and not m.group(1).startswith("127.") and not iface.startswith(("utun", "llw", "awdl")):
                label = ("VM network" if iface.startswith(("vmnet", "bridge1")) else
                         "Wi-Fi / LAN" if iface.startswith("en") else iface)
                found.append({"url": f"http://{m.group(1)}:{port}", "label": label, "iface": iface})
    except (OSError, subprocess.SubprocessError):
        pass
    if not found:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                found.append({"url": f"http://{s.getsockname()[0]}:{port}", "label": "LAN", "iface": ""})
        except OSError:
            pass
    public = os.environ.get("AEGIS_PUBLIC_URL")
    if public:
        found.insert(0, {"url": public.rstrip("/"), "label": "Public URL", "iface": "public"})
    return found


# ------------------------------------------------------------------ LAN discovery
class _Discovery(asyncio.DatagramProtocol):
    """Answers setup.ps1's broadcast ("AEGIS-DISCOVER") with the address that laptop can reach us on."""

    def __init__(self, port: int):
        self.port = port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if not data.startswith(b"AEGIS-DISCOVER"):
            return
        try:  # pick our address on the interface that faces the sender
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((addr[0], addr[1] or 9))
                mine = s.getsockname()[0]
        except OSError:
            return
        reply = {"aegis": "console", "url": f"http://{mine}:{self.port}", "name": socket.gethostname()}
        self.transport.sendto(json.dumps(reply).encode(), addr)


async def start_discovery(http_port: int) -> None:
    try:
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _Discovery(http_port), local_addr=("0.0.0.0", DISCOVERY_PORT), allow_broadcast=True)
    except OSError as e:  # port taken (second backend running): the subnet scan still finds us
        print(f"[aegis] LAN discovery disabled: {e}")


# ------------------------------------------------------------------ routes
class ProgressIn(BaseModel, extra="allow"):
    install_id: str
    step: Optional[str] = None
    state: Optional[str] = None
    detail: Optional[str] = None


class EnrollIn(BaseModel):
    install_id: str
    hostname: Optional[str] = None
    agent_id: Optional[str] = None


class RemovedIn(BaseModel):
    agent_id: str


class JoinIn(BaseModel):
    hostname: Optional[str] = None
    user: Optional[str] = None
    os: Optional[str] = None
    arch: Optional[str] = None


class FlagIn(BaseModel):
    on: bool


def router(enr: Enrollment, broadcast: Callable, queue_command: Callable) -> APIRouter:
    r = APIRouter()

    async def push(inst: Optional[Dict[str, Any]]) -> None:
        if inst:
            await broadcast({"type": "install", "install": inst})

    # ---- discovery + join requests (used by the public setup.ps1; no token yet)
    @r.get("/api/discover")
    async def discover(request: Request):
        return {"aegis": "console", "name": socket.gethostname(), "url": str(request.base_url).rstrip("/")}

    @r.post("/api/enroll/request")
    async def join(body: JoinIn, request: Request):
        req = enr.new_request(body.model_dump(), request.client.host if request.client else None)
        await broadcast({"type": "join_request", "request": enr.public_request(req)})
        return {"id": req["id"], "status": req["status"]}

    @r.get("/api/enroll/request/{rid}")
    async def join_status(rid: str, request: Request):
        req = enr.requests.get(rid)
        if not req:
            raise HTTPException(404, "request expired; run setup again")
        out = {"id": rid, "status": req["status"]}
        if req["status"] == "approved":
            out |= {"token": enr.token, "server": str(request.base_url).rstrip("/")}
        return out

    @r.post("/api/enroll/request/{rid}/{decision}")
    async def decide(rid: str, decision: str):
        if decision not in ("approve", "deny"):
            raise HTTPException(404)
        req = enr.decide(rid, decision == "approve")
        if not req:
            raise HTTPException(409, "request is no longer pending")
        await broadcast({"type": "join_request", "request": enr.public_request(req)})
        return enr.public_request(req)

    @r.post("/api/enroll/auto_approve")
    async def auto_approve(body: FlagIn):
        enr.set_auto_approve(body.on)
        return {"auto_approve": enr.auto_approve}

    @r.get("/install.ps1")
    async def install_script(request: Request, t: str = ""):
        try:
            enr.check_enroll(t)
        except HTTPException:
            msg = "This Aegis install command has expired. Copy a fresh one from the console (Endpoints > Add endpoint)."
            return PlainTextResponse(f"Write-Host '{msg}' -ForegroundColor Red\n", media_type="text/plain")
        server = str(request.base_url).rstrip("/")  # the address this laptop used to reach us
        src = (AGENT_DIR / "setup" / "install.ps1").read_text(encoding="utf-8")
        src = src.replace("__SERVER__", server).replace("__TOKEN__", t)
        return PlainTextResponse(src, media_type="text/plain")

    @r.get("/uninstall.ps1")
    async def uninstall_script():
        return FileResponse(PAYLOAD_FILES["uninstall.ps1"], media_type="text/plain")

    @r.get("/api/enroll/payload/{name}")
    async def payload(name: str, t: str = ""):
        enr.check_enroll(t)
        path = PAYLOAD_FILES.get(name)
        if not path or not path.exists():
            raise HTTPException(404, f"{name} is missing on the console; run backend/fetch_payload.sh")
        if name == "sysmonconfig.xml":
            # SwiftOnSecurity logs no ProcessAccess; we need access to lsass.exe for credential-theft detection
            cfg = path.read_text(encoding="utf-8")
            cfg = cfg.replace('<ProcessAccess onmatch="include">',
                              '<ProcessAccess onmatch="include"><TargetImage condition="end with">\\lsass.exe</TargetImage>', 1)
            return Response(cfg, media_type="application/xml")
        return FileResponse(path, filename=name)

    @r.post("/api/enroll/progress")
    async def progress(body: ProgressIn, request: Request, x_enroll_token: Optional[str] = Header(None)):
        enr.check_enroll(x_enroll_token)
        inst = enr.progress(body.model_dump(), request.client.host if request.client else None)
        await push(inst)
        return {"ok": True}

    @r.post("/api/enroll")
    async def enroll(body: EnrollIn, x_enroll_token: Optional[str] = Header(None)):
        enr.check_enroll(x_enroll_token)
        if not enr.get(body.install_id):
            raise HTTPException(400, "unknown install id")
        return enr.enroll(body.model_dump())

    @r.get("/api/enroll/installs/{install_id}")
    async def install_status(install_id: str, x_enroll_token: Optional[str] = Header(None)):
        enr.check_enroll(x_enroll_token)
        inst = enr.get(install_id)
        if not inst:
            raise HTTPException(404)
        return inst

    @r.post("/api/enroll/removed")
    async def removed(body: RemovedIn, x_agent_token: Optional[str] = Header(None)):
        enr.check_agent(x_agent_token, body.agent_id)
        enr.remove_agent(body.agent_id)
        await broadcast({"type": "agent_removed", "agent_id": body.agent_id})
        return {"ok": True}

    # ---- dashboard
    @r.get("/api/enroll/info")
    async def info(request: Request):
        port = request.url.port or 8000
        return {"token": enr.token, "addresses": lan_addresses(port), "steps": [{"id": s, "label": l} for s, l in STEPS],
                "installs": enr.recent(), "requests": enr.pending(), "auto_approve": enr.auto_approve,
                "payload_ready": all(p.exists() for p in PAYLOAD_FILES.values())}

    @r.post("/api/enroll/rotate")
    async def rotate():
        return {"token": enr.rotate()}

    @r.delete("/api/agents/{agent_id}")
    async def remove(agent_id: str, uninstall: bool = False):
        """uninstall=true asks the agent to remove itself; otherwise just forget the endpoint."""
        if uninstall:
            return await queue_command(agent_id, "uninstall", {})
        enr.remove_agent(agent_id)
        await broadcast({"type": "agent_removed", "agent_id": agent_id})
        return {"ok": True}

    return r
