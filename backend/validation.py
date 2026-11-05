"""'Test my protection': run a harmless simulation on an endpoint and verify every
stage of the pipeline caught it — the test ran, its telemetry arrived, the expected
rule fired, and an incident exists to investigate.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from normalize import now_iso

TESTS = {
    "encoded_powershell": {
        "title": "Encoded PowerShell",
        "description": "Starts a hidden PowerShell with a base64-encoded command (it only sleeps), the way malware hides payloads.",
        "rule_id": "EXEC-001",
        "technique": "T1059.001",
    },
    "recon_burst": {
        "title": "Reconnaissance burst",
        "description": "Runs whoami, hostname, ipconfig and net user in quick succession, like an intruder taking stock.",
        "rule_id": "DISC-001",
        "technique": "T1082",
    },
    "ransomware_sim": {
        "title": "Ransomware",
        "description": "Seeds a folder of throwaway documents and starts encrypting them; the canary kill-switch should stop it within seconds.",
        "rule_id": "IMP-002",
        "technique": "T1486",
    },
}
TIMEOUT_S = 45  # after the test runs, how long telemetry and detection get before we call it missing

SCHEMA = """
CREATE TABLE IF NOT EXISTS validations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, test TEXT, command_id INTEGER, started_at TEXT
);
"""


def _t(iso: Optional[str]) -> Optional[datetime]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


class Validator:
    def __init__(self, db):
        self.db = db
        with db.lock, db.conn:
            db.conn.executescript(SCHEMA)

    def _one(self, sql, args):
        with self.db.lock:
            return self.db.conn.execute(sql, args).fetchone()

    def start(self, agent_id: str, test: str) -> Dict[str, Any]:
        cmd = self.db.add_command(agent_id, "run_test", {"test": test})
        with self.db.lock, self.db.conn:
            cur = self.db.conn.execute(
                "INSERT INTO validations (agent_id, test, command_id, started_at) VALUES (?,?,?,?)",
                (agent_id, test, cmd["id"], now_iso()))
            vid = cur.lastrowid
        return self.state(vid)

    def latest(self, agent_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT id FROM validations " + ("WHERE agent_id=? " if agent_id else "") + "ORDER BY id DESC LIMIT 1",
                        (agent_id,) if agent_id else ())
        return self.state(row["id"]) if row else None

    def state(self, vid: int) -> Optional[Dict[str, Any]]:
        v = self._one("SELECT * FROM validations WHERE id=?", (vid,))
        if not v:
            return None
        spec = TESTS[v["test"]]
        cmd = self._one("SELECT * FROM commands WHERE id=?", (v["command_id"],))
        now = datetime.now(timezone.utc)
        result = json.loads(cmd["result"]) if cmd and cmd["result"] else {}
        pids = [str(p) for p in (result.get("pids") or ([result["pid"]] if result.get("pid") else []))]
        ran_at = cmd["completed_at"] if cmd else None
        late = bool(ran_at and (now - _t(ran_at)).total_seconds() > TIMEOUT_S)

        steps: List[Dict[str, Any]] = []
        # 1. the agent ran the simulation
        cs = cmd["status"] if cmd else "missing"
        steps.append({"key": "ran", "label": "Drill ran",
                      "state": {"done": "done", "failed": "fail", "expired": "fail"}.get(cs, "active"),
                      "at": ran_at, "detail": result.get("error") or ("Agent offline, test never started" if cs == "expired" else None)})

        # 2. its process events reached the backend
        ev = None
        if pids:
            marks = ",".join("?" * len(pids))
            ev = self._one(
                f"SELECT id, received_at FROM events WHERE agent_id=? AND event_id=1 AND channel LIKE '%Sysmon%' "
                f"AND json_extract(data,'$.ProcessId') IN ({marks}) ORDER BY id LIMIT 1", (v["agent_id"], *pids))
        steps.append({"key": "telemetry", "label": "Event received", "at": ev["received_at"] if ev else None,
                      "state": "done" if ev else ("fail" if late else "active" if steps[0]["state"] == "done" else "todo"),
                      "detail": None if ev or not late else "The process ran but no Sysmon event arrived. Check the agent and Sysmon config.",
                      "event_id": ev["id"] if ev else None})

        # 3. the expected rule fired on it
        al = self._one("SELECT id, created_at FROM alerts WHERE agent_id=? AND rule_id=? AND created_at>=? ORDER BY id LIMIT 1",
                       (v["agent_id"], spec["rule_id"], v["started_at"]))
        steps.append({"key": "rule", "label": "Rule fired", "sub": spec["rule_id"], "at": al["created_at"] if al else None,
                      "state": "done" if al else ("fail" if late and ev else "active" if ev else "todo"),
                      "detail": None if al or not (late and ev) else f"Telemetry arrived but {spec['rule_id']} did not fire.",
                      "alert_id": al["id"] if al else None})

        # 4. an incident is waiting for the analyst
        steps.append({"key": "incident", "label": "Case opened", "at": al["created_at"] if al else None,
                      "state": "done" if al else ("fail" if steps[2]["state"] == "fail" else "todo"),
                      "alert_id": al["id"] if al else None})

        states = [s["state"] for s in steps]
        status = "failed" if "fail" in states else "passed" if all(s == "done" for s in states) else "running"
        took = None
        if status == "passed":
            took = round((_t(al["created_at"]) - _t(v["started_at"])).total_seconds(), 2)
        return {"id": v["id"], "agent_id": v["agent_id"], "test": v["test"], "spec": spec, "started_at": v["started_at"],
                "status": status, "seconds": took, "steps": steps}
