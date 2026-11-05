"""
Judge mode: a phone page, reached by QR code, that lets judges fire one of the harmless drills at the demo
laptop and watch it get caught. The operator opens a session from the (password-protected) dashboard; the
session's random token is the only credential the public page has. Only allowlisted drills, one at a time,
with a cooldown and a per-session cap. Ending the session or letting it expire kills the link.
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional

from validation import TESTS

SESSION_S = 60 * 60
COOLDOWN_S = 15
MAX_RUNS = 40
PUBLIC_TESTS = ("encoded_powershell", "recon_burst", "ransomware_sim")


class Judge:
    def __init__(self, db, validator):
        self.db = db
        self.validator = validator
        self.session: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------ operator side
    def open(self, agent_id: str) -> Dict[str, Any]:
        self.session = {"token": secrets.token_urlsafe(12), "agent_id": agent_id,
                        "expires": time.time() + SESSION_S, "runs": [], "last_run": 0.0}
        return self.public_session()

    def close(self) -> None:
        self.session = None

    def public_session(self) -> Dict[str, Any]:
        s = self.live()
        if not s:
            return {}
        return {"token": s["token"], "agent_id": s["agent_id"], "expires_in": int(s["expires"] - time.time()),
                "runs": len(s["runs"]), "max_runs": MAX_RUNS}

    def live(self) -> Optional[Dict[str, Any]]:
        if self.session and time.time() > self.session["expires"]:
            self.session = None
        return self.session

    def check(self, token: str) -> Optional[Dict[str, Any]]:
        s = self.live()
        return s if s and secrets.compare_digest(s["token"], token) else None

    # ------------------------------------------------------------ public side
    def state(self, s: Dict[str, Any]) -> Dict[str, Any]:
        agent = next((a for a in self.db.list_agents() if a["id"] == s["agent_id"]), None)
        run = self.validator.state(s["runs"][-1]) if s["runs"] else None
        out: Dict[str, Any] = {
            "host": agent["hostname"] if agent else "unknown",
            "last_seen": agent["last_seen"] if agent else None,
            "tests": [{"id": t, "title": TESTS[t]["title"], "description": TESTS[t]["description"],
                       "technique": TESTS[t]["technique"], "rule_id": TESTS[t]["rule_id"]} for t in PUBLIC_TESTS],
            "cooldown": max(0, int(s["last_run"] + COOLDOWN_S - time.time())),
            "runs_left": MAX_RUNS - len(s["runs"]),
            "expires_in": int(s["expires"] - time.time()),
            "run": None,
        }
        if run:
            r = {"test": run["test"], "title": run["spec"]["title"], "status": run["status"], "seconds": run["seconds"],
                 "started_at": run["started_at"],
                 "steps": [{"label": x["label"], "state": x["state"], "at": x.get("at")} for x in run["steps"]]}
            aid = next((x.get("alert_id") for x in run["steps"] if x.get("alert_id")), None)
            al = self.db.get_alert(aid) if aid else None
            if al:
                ctx = al.get("context") or {}
                kills = [c for c in self.db.commands_for_alert(aid) if c["type"] == "kill_process" and c["status"] == "done"]
                r["case"] = {"id": al["id"], "created_at": al["created_at"], "rule": al["rule_title"], "technique": al["technique"], "technique_name": al["technique_name"],
                             "severity": al["severity"], "status": al["status"]}
                if ctx.get("Action") == "killed" and ctx.get("KillMs"):
                    r["case"]["killed"] = f"Killed on the laptop {ctx['KillMs']} ms after the decoy was hit, {ctx.get('FilesAffected', '?')} files touched"
                elif kills:
                    k = kills[-1]
                    r["case"]["killed"] = "Killed by the analyst from the console"
                an = al.get("analysis")
                if an:
                    r["case"]["ai"] = {"verdict": an.get("verdict"), "headline": an.get("headline"), "story": an.get("story"),
                                       "source": an.get("source")}
            out["run"] = r
        return out

    def run(self, s: Dict[str, Any], test: str) -> Dict[str, Any]:
        if test not in PUBLIC_TESTS:
            return {"error": "That drill is not available."}
        if len(s["runs"]) >= MAX_RUNS:
            return {"error": "This judge session has used all its drills."}
        wait = int(s["last_run"] + COOLDOWN_S - time.time())
        if wait > 0:
            return {"error": f"One drill at a time. Try again in {wait} s."}
        if s["runs"]:
            prev = self.validator.state(s["runs"][-1])
            if prev and prev["status"] == "running":
                return {"error": "The last drill is still running."}
        v = self.validator.start(s["agent_id"], test)
        s["runs"].append(v["id"])
        s["last_run"] = time.time()
        return {"ok": True, "validation": v}
