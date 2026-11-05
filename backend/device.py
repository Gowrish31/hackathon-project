"""
"My device" page: what the person whose laptop runs the agent gets to see. It is read-only (status, cases,
recent activity) with one action, uninstalling the agent. No kill, isolate, drill or update controls.

Each enrolled agent can have a random view token; the admin console hands out /device/<token>, and that token
is the only credential the public page has. Removing the agent deletes its row, which kills the link.
"""
from __future__ import annotations

import secrets
from collections import Counter
from typing import Any, Dict, Optional


class Devices:
    def __init__(self, db):
        self.db = db
        with db.lock, db.conn:
            cols = {r[1] for r in db.conn.execute("PRAGMA table_info(agents)")}
            if "view_token" not in cols:
                db.conn.execute("ALTER TABLE agents ADD COLUMN view_token TEXT")

    # ------------------------------------------------------------ admin side
    def link(self, agent_id: str, rotate: bool = False) -> Optional[str]:
        with self.db.lock, self.db.conn:
            row = self.db.conn.execute("SELECT view_token FROM agents WHERE id=?", (agent_id,)).fetchone()
            if not row:
                return None
            tok = row["view_token"]
            if rotate or not tok:
                tok = secrets.token_urlsafe(12)
                self.db.conn.execute("UPDATE agents SET view_token=? WHERE id=?", (tok, agent_id))
        return tok

    # ------------------------------------------------------------ public side
    def agent_for(self, token: str) -> Optional[Dict[str, Any]]:
        if not token or len(token) < 12:
            return None
        for a in self.db.list_agents():
            if a.get("view_token") and secrets.compare_digest(a["view_token"], token):
                return a
        return None

    def state(self, a: Dict[str, Any]) -> Dict[str, Any]:
        info = a.get("info") or {}
        iso = info.get("isolation") or {}
        cmds = self.db.list_commands(a["id"], 30)
        # the heartbeat's isolation flag can lag; the last finished isolate/release command is the truth
        last_iso = next((c for c in cmds if c["type"] in ("isolate_host", "release_host") and c["status"] == "done"), None)
        isolated = (last_iso["type"] == "isolate_host") if last_iso else bool(iso.get("isolated"))
        unin = next((c for c in cmds if c["type"] == "uninstall"), None)

        cases = []
        for al in self.db.list_alerts(25, agent_id=a["id"]):
            ctx = al.get("context") or {}
            c = {"id": al["id"], "title": al["title"] or al["rule_title"], "rule": al["rule_title"],
                 "description": al.get("description"), "severity": al["severity"], "status": al["status"],
                 "technique": al["technique"], "technique_name": al["technique_name"], "tactic": al["tactic"],
                 "created_at": al["created_at"]}
            if ctx.get("Action") == "killed" and ctx.get("KillMs"):
                c["response"] = f"Stopped on this laptop {ctx['KillMs']} ms after the decoy files were touched"
            elif any(k["type"] == "kill_process" and k["status"] == "done" for k in self.db.commands_for_alert(al["id"])):
                c["response"] = "The security team stopped the process"
            an = al.get("analysis")
            if an:
                c["ai"] = {"verdict": an.get("verdict"), "headline": an.get("headline"), "story": an.get("story")}
            cases.append(c)

        events = self.db.list_events(60, a["id"])
        cats = Counter(e["category"] for e in self.db.list_events(500, a["id"]))
        return {
            "host": a["hostname"], "os": a.get("os"), "arch": info.get("arch"), "user": a.get("user"),
            "ip": a.get("ip"), "version": a.get("agent_version"), "installed": info.get("mode") == "service",
            "is_admin": a.get("is_admin"), "first_seen": a.get("first_seen"), "last_seen": a.get("last_seen"),
            "events_sent": info.get("events_sent", 0), "channels": info.get("channels") or [],
            "canary_armed": (info.get("canary") or {}).get("armed"),
            "isolated": isolated,
            "uninstall": {"status": unin["status"], "created_at": unin["created_at"]} if unin else None,
            "cases": cases,
            "activity": [{"id": e["id"], "ts": e["ts"], "category": e["category"], "summary": e["summary"]} for e in events],
            "categories": dict(cats.most_common()),
        }
