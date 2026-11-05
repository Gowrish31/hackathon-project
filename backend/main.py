"""
Aegis backend: ingest API for agents, REST + WebSocket for the dashboard.

    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from db import DB
from enroll import Enrollment, router as enroll_router, start_discovery
from detection import DetectionEngine
from normalize import estimate_skew, normalize
from tree import TreeBuilder
from validation import TESTS, Validator
from analyst import Analyst
from judge import Judge
from device import Devices

AGENT_TOKEN = os.environ.get("AEGIS_TOKEN", "hackathon-demo-token")
HERE = Path(__file__).parent
DB_PATH = os.environ.get("AEGIS_DB", str(HERE / "aegis.db"))
db = DB(DB_PATH)
engine = DetectionEngine(HERE / "rules")
trees = TreeBuilder(db)
validator = Validator(db)
enrollment = Enrollment(db)
analyst = Analyst(db, DB_PATH)
judge = Judge(db, validator)
devices = Devices(db)

app = FastAPI(title="Aegis SIEM/EDR")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------------ live push
class Hub:
    def __init__(self) -> None:
        self.clients: Set[WebSocket] = set()

    async def broadcast(self, msg: Dict[str, Any]) -> None:
        text = json.dumps(msg)
        for ws in list(self.clients):
            try:
                await ws.send_text(text)
            except Exception:
                self.clients.discard(ws)


hub = Hub()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # we only push; this just detects disconnects
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


# ------------------------------------------------------------------ models
class Heartbeat(BaseModel, extra="allow"):
    agent_id: str
    hostname: str
    ip: Optional[str] = None
    os: Optional[str] = None
    user: Optional[str] = None
    agent_version: Optional[str] = None
    is_admin: bool = False


class RawEvent(BaseModel):
    ts: Optional[str] = None
    channel: str
    provider: Optional[str] = None
    event_id: int
    record_id: Optional[int] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class IngestBatch(BaseModel):
    agent_id: str
    hostname: str
    sent_at: Optional[str] = None  # agent clock at send time, used to correct clock skew
    events: List[RawEvent]


class CommandIn(BaseModel):
    type: str
    args: Dict[str, Any] = Field(default_factory=dict)


class AlertUpdate(BaseModel):
    status: str  # open | acknowledged | contained | closed


class CommandResult(BaseModel):
    status: str
    result: Any = None


def check_token(token: Optional[str], agent_id: Optional[str] = None) -> None:
    enrollment.check_agent(token, agent_id)


# ------------------------------------------------------------------ agent-facing
@app.post("/api/agents/heartbeat")
async def heartbeat(hb: Heartbeat, x_agent_token: Optional[str] = Header(None)):
    check_token(x_agent_token, hb.agent_id)
    agent = db.upsert_agent(hb.model_dump())
    await hub.broadcast({"type": "agent", "agent": agent})
    inst = enrollment.on_heartbeat(hb.agent_id, hb.model_dump())
    if inst:
        await hub.broadcast({"type": "install", "install": inst})
    return {"ok": True}


@app.post("/api/ingest")
async def ingest(batch: IngestBatch, x_agent_token: Optional[str] = Header(None)):
    check_token(x_agent_token, batch.agent_id)
    skew = estimate_skew(batch.sent_at, [e.ts for e in batch.events])
    events = [normalize(e.model_dump(), skew) for e in batch.events
              if not (e.channel == "Security" and e.event_id == 4688)]  # Sysmon 1 covers this
    if not events:
        return {"ok": True, "count": 0}
    stored = db.insert_events(batch.agent_id, batch.hostname, events)
    await hub.broadcast({"type": "events", "events": stored})
    inst = enrollment.on_ingest(batch.agent_id, len(stored))
    if inst:
        await hub.broadcast({"type": "install", "install": inst})
    alerts = db.insert_alerts(engine.evaluate(stored))
    for i, a in enumerate(alerts):
        # the agent already killed the process behind a tripped canary: the case starts contained
        if a.get("rule_id") == "IMP-002" and (a.get("context") or {}).get("Action") == "killed":
            alerts[i] = a = db.update_alert(a["id"], status="contained") or a
        await hub.broadcast({"type": "alert", "alert": a})
    return {"ok": True, "count": len(stored), "alerts": len(alerts)}


@app.get("/api/agents/{agent_id}/commands/pending")
async def pending_commands(agent_id: str, x_agent_token: Optional[str] = Header(None)):
    check_token(x_agent_token, agent_id)
    cmds = db.take_pending(agent_id)
    for c in cmds:
        await hub.broadcast({"type": "command", "command": c})
    return cmds


@app.post("/api/commands/{cid}/result")
async def command_result(cid: int, res: CommandResult, x_agent_token: Optional[str] = Header(None)):
    check_token(x_agent_token)
    cmd = db.complete_command(cid, res.status, res.result)
    if not cmd:
        raise HTTPException(404)
    await hub.broadcast({"type": "command", "command": cmd})
    # A successful response action tied to an alert auto-contains that alert.
    alert_id = (cmd.get("args") or {}).get("alert_id")
    if res.status == "done" and cmd["type"] == "kill_process" and alert_id:
        a = db.get_alert(int(alert_id))
        if a and a["status"] in ("open", "acknowledged"):
            a = db.update_alert(int(alert_id), status="contained")
            if a:
                await hub.broadcast({"type": "alert", "alert": a})
    return {"ok": True}


# ------------------------------------------------------------------ dashboard-facing
@app.get("/api/agents")
async def list_agents():
    return db.list_agents()


@app.get("/api/events")
async def list_events(limit: int = 300, agent_id: Optional[str] = None, category: Optional[str] = None,
                      q: Optional[str] = None, before_id: Optional[int] = None):
    return db.list_events(limit, agent_id, category, q, before_id)


@app.get("/api/stats")
async def stats():
    return db.stats()


async def enqueue(agent_id: str, ctype: str, args: Dict[str, Any]) -> Dict[str, Any]:
    c = db.add_command(agent_id, ctype, args)
    await hub.broadcast({"type": "command", "command": c})
    return c


@app.post("/api/agents/{agent_id}/commands")
async def queue_command(agent_id: str, cmd: CommandIn):
    return await enqueue(agent_id, cmd.type, cmd.args)


@app.get("/api/agents/{agent_id}/commands")
async def list_commands(agent_id: str):
    return db.list_commands(agent_id)


@app.get("/api/alerts")
async def list_alerts(limit: int = 200, status: Optional[str] = None, agent_id: Optional[str] = None,
                      severity: Optional[str] = None):
    return db.list_alerts(limit, status, agent_id, severity)


@app.get("/api/alerts/{aid}")
async def get_alert(aid: int):
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404)
    return a | {"events": db.events_by_ids(a["event_ids"])}


class AnalyzeIn(BaseModel):
    known: List[Dict[str, Any]] = Field(default_factory=list)
    open: List[Dict[str, Any]] = Field(default_factory=list)


@app.get("/api/analyst/status")
async def analyst_status():
    return analyst.status()


@app.post("/api/alerts/{aid}/analyze")
async def analyze_alert(aid: int, body: AnalyzeIn, refresh: bool = False):
    """AI analyst write-up for a case. Cached on the alert; ?refresh=1 rewrites it."""
    a = await analyst.analyze(aid, body.model_dump(), refresh)
    if not a:
        raise HTTPException(404)
    await hub.broadcast({"type": "alert", "alert": a})
    return a


@app.get("/api/alerts/{aid}/tree")
async def alert_tree(aid: int):
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404)
    return trees.build(a) or {"root": None}


class ValidationIn(BaseModel):
    agent_id: str
    test: str = "encoded_powershell"


@app.get("/api/validation/tests")
async def validation_tests():
    return [{"id": k, **v} for k, v in TESTS.items()]


@app.post("/api/validation/run")
async def validation_run(body: ValidationIn):
    if body.test not in TESTS:
        raise HTTPException(400, f"unknown test; choose one of {', '.join(TESTS)}")
    v = validator.start(body.agent_id, body.test)
    await hub.broadcast({"type": "validation", "validation": v})
    return v


@app.get("/api/validation/latest")
async def validation_latest(agent_id: Optional[str] = None):
    return validator.latest(agent_id) or {}


@app.get("/api/validation/{vid}")
async def validation_get(vid: int):
    v = validator.state(vid)
    if not v:
        raise HTTPException(404)
    return v


# ------------------------------------------------------------ judge mode
class JudgeOpen(BaseModel):
    agent_id: str


class JudgeRun(BaseModel):
    test: str


@app.get("/api/judge/session")
async def judge_session():
    return judge.public_session()


@app.post("/api/judge/session")
async def judge_open(body: JudgeOpen):
    if not any(a["id"] == body.agent_id for a in db.list_agents()):
        raise HTTPException(404, "unknown endpoint")
    return judge.open(body.agent_id)


@app.delete("/api/judge/session")
async def judge_close():
    judge.close()
    return {"ok": True}


# public (no console login): the token in the path is the credential
@app.get("/judge/{token}")
async def judge_page(token: str):
    return FileResponse(HERE / "judge.html", media_type="text/html", headers={"Cache-Control": "no-store"})


@app.get("/api/judge/{token}/state")
async def judge_state(token: str):
    s = judge.check(token)
    if not s:
        raise HTTPException(404, "This judge link has expired.")
    st = judge.state(s)
    c = (st.get("run") or {}).get("case")
    # nobody watching the console? write the AI summary ourselves after a short grace period
    if c and "ai" not in c and c["id"] not in analyst.inflight:
        from datetime import datetime, timezone
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(c["created_at"].replace("Z", "+00:00"))).total_seconds()
        if age > 8:
            async def _bg(aid=c["id"]):
                a = await analyst.analyze(aid)
                if a:
                    await hub.broadcast({"type": "alert", "alert": a})
            asyncio.ensure_future(_bg())
    return st


@app.post("/api/judge/{token}/run")
async def judge_run(token: str, body: JudgeRun):
    s = judge.check(token)
    if not s:
        raise HTTPException(404, "This judge link has expired.")
    r = judge.run(s, body.test)
    if r.get("error"):
        raise HTTPException(429, r["error"])
    await hub.broadcast({"type": "validation", "validation": r["validation"]})
    return judge.state(s)


# ------------------------------------------------------------ "my device" page (for the laptop's owner)
@app.post("/api/agents/{agent_id}/device_link")
async def device_link(agent_id: str, rotate: bool = False):
    """Console only: the private read-only link for one laptop. ?rotate=1 kills the old link."""
    tok = devices.link(agent_id, rotate)
    if not tok:
        raise HTTPException(404, "unknown endpoint")
    return {"token": tok, "path": f"/device/{tok}"}


# public (no console login): the token in the path is the credential
@app.get("/device/{token}")
async def device_page(token: str):
    return FileResponse(HERE / "device.html", media_type="text/html", headers={"Cache-Control": "no-store"})


def _device(token: str) -> Dict[str, Any]:
    a = devices.agent_for(token)
    if not a:
        raise HTTPException(404, "This link is no longer valid.")
    return a


@app.get("/api/device/{token}/state")
async def device_state(token: str):
    return devices.state(_device(token))


@app.post("/api/device/{token}/uninstall")
async def device_uninstall(token: str):
    a = _device(token)
    if (a.get("info") or {}).get("mode") != "service":
        raise HTTPException(409, "This agent was started by hand, so it cannot remove itself. Ask the security team.")
    pending = next((c for c in db.list_commands(a["id"], 10)
                    if c["type"] == "uninstall" and c["status"] in ("pending", "sent")), None)
    if not pending:
        await enqueue(a["id"], "uninstall", {"requested_by": "device owner"})
    return devices.state(a)


@app.get("/api/events/{eid}")
async def get_event(eid: int):
    ev = db.events_by_ids([eid])
    if not ev:
        raise HTTPException(404)
    return ev[0]


@app.get("/api/response/summary")
async def response_summary():
    return db.response_summary()


@app.get("/api/alerts/{aid}/commands")
async def alert_commands(aid: int):
    return db.commands_for_alert(aid)


@app.patch("/api/alerts/{aid}")
async def update_alert(aid: int, upd: AlertUpdate):
    if upd.status not in ("open", "acknowledged", "contained", "closed"):
        raise HTTPException(400, "status must be open|acknowledged|contained|closed")
    a = db.update_alert(aid, status=upd.status)
    if not a:
        raise HTTPException(404)
    await hub.broadcast({"type": "alert", "alert": a})
    return a


@app.get("/api/rules")
async def list_rules():
    return [r.public() | {"source": r.source} for r in engine.rules]


@app.post("/api/rules/reload")
async def reload_rules():
    try:
        engine.load()
    except Exception as e:  # bad YAML: keep the old rules loaded
        raise HTTPException(400, f"rule load failed: {e}")
    return {"ok": True, "rules": len(engine.rules)}


app.include_router(enroll_router(enrollment, hub.broadcast, enqueue))


@app.on_event("startup")
async def _lan_discovery():
    # setup.ps1 from the public download page broadcasts on UDP 47800 to find this console
    await start_discovery(int(os.environ.get("AEGIS_PORT", "8000")))

AGENT_FILES = {"agent.py", "requirements.txt", "install_sysmon.ps1", "install.ps1", "uninstall.ps1"}


@app.get("/api/agent/files/{name}")
async def agent_file(name: str):
    """Lets the VM pull the latest agent with one `iwr` line (no clipboard / file share needed)."""
    if name not in AGENT_FILES:
        raise HTTPException(404)
    path = HERE.parent / "agent" / ("setup" if name.endswith(".ps1") else "") / name
    return FileResponse(path, media_type="text/plain")


@app.get("/api/health")
async def health():
    return {"ok": True}


# serve the built dashboard (npm run build) so demo day needs only one process
DIST = HERE.parent / "dashboard" / "dist"
if DIST.exists():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="dashboard")
