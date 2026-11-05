"""Rebuild a process tree around an alert from stored Sysmon telemetry.

Sysmon gives every process a ProcessGuid and its parent's ParentProcessGuid, so we
walk up (ancestors), down (children / grandchildren) and attach what each process
did (network, DNS, file, registry, process access) from the other Sysmon events.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

SYSMON = "Microsoft-Windows-Sysmon/Operational"
MAX_UP, MAX_DEPTH, MAX_CHILDREN, MAX_NODES, MAX_ACTIVITY = 4, 3, 8, 30, 6

# Sysmon event id -> activity kind shown under a process
ACTIVITY = {3: "network", 22: "dns", 11: "file", 12: "registry", 13: "registry", 10: "access", 8: "inject"}


def _base(p: str) -> str:
    return (p or "").replace("/", "\\").split("\\")[-1]


class TreeBuilder:
    def __init__(self, db):
        self.db = db

    def _q(self, sql: str, args) -> List[Dict[str, Any]]:
        with self.db.lock:
            rows = self.db.conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d["data"] or "{}")
            out.append(d)
        return out

    def _proc_event(self, agent_id: str, guid: str) -> Optional[Dict[str, Any]]:
        rows = self._q(
            "SELECT * FROM events WHERE agent_id=? AND channel=? AND event_id=1 "
            "AND json_extract(data,'$.ProcessGuid')=? ORDER BY id DESC LIMIT 1", (agent_id, SYSMON, guid))
        return rows[0] if rows else None

    def _node(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        d = ev["data"]
        return {
            "guid": d.get("ProcessGuid"), "pid": d.get("ProcessId"), "image": d.get("Image"),
            "name": _base(d.get("Image")), "cmd": d.get("CommandLine"), "user": d.get("User"),
            "integrity": d.get("IntegrityLevel"), "ts": ev["ts"], "event_id": ev["id"],
            "children": [], "activity": [],
        }

    @staticmethod
    def _stub_parent(d: Dict[str, Any]) -> Dict[str, Any]:
        """Parent we never saw start (it launched before logging) — reconstruct from the child's fields."""
        return {
            "guid": d.get("ParentProcessGuid"), "pid": d.get("ParentProcessId"), "image": d.get("ParentImage"),
            "name": _base(d.get("ParentImage")), "cmd": d.get("ParentCommandLine"), "user": d.get("ParentUser"),
            "integrity": None, "ts": None, "event_id": None, "children": [], "activity": [], "stub": True,
        }

    def focus_guid(self, alert: Dict[str, Any]) -> Optional[str]:
        ctx = alert.get("context") or {}
        guid = ctx.get("ProcessGuid") or ctx.get("SourceProcessGuid")
        if guid:
            return guid
        ids = alert.get("event_ids") or []
        if ids:
            evs = self._q(f"SELECT * FROM events WHERE id IN ({','.join('?' * len(ids))})", ids)
            for ev in evs:
                g = ev["data"].get("ProcessGuid") or ev["data"].get("SourceProcessGuid")
                if g:
                    return g
            # PowerShell 4104 has no GUID: match the powershell process by PID near the alert time
            for ev in evs:
                pid = ev["data"].get("ProcessId") or ev["data"].get("ExecutionProcessID")
                if pid:
                    rows = self._q(
                        "SELECT * FROM events WHERE agent_id=? AND channel=? AND event_id=1 "
                        "AND json_extract(data,'$.ProcessId')=? AND ts<=? ORDER BY ts DESC LIMIT 1",
                        (alert["agent_id"], SYSMON, str(pid), alert["ts"]))
                    if rows:
                        return rows[0]["data"].get("ProcessGuid")
        return None

    def build(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        agent_id = alert["agent_id"]
        guid = self.focus_guid(alert)
        if not guid:
            return None
        ev = self._proc_event(agent_id, guid)
        if ev:
            focus = self._node(ev)
        else:
            ctx = alert.get("context") or {}
            img = ctx.get("Image") or ctx.get("SourceImage")
            if not img:
                return None
            focus = {"guid": guid, "pid": ctx.get("ProcessId") or ctx.get("SourceProcessId"), "image": img,
                     "name": _base(img), "cmd": ctx.get("CommandLine"), "user": ctx.get("User"), "integrity": None,
                     "ts": alert["ts"], "event_id": None, "children": [], "activity": []}
        focus["focus"] = True
        nodes = {guid: focus}

        # descendants (BFS)
        frontier = [focus]
        for _depth in range(MAX_DEPTH):
            nxt = []
            for parent in frontier:
                kids = self._q(
                    "SELECT * FROM events WHERE agent_id=? AND channel=? AND event_id=1 "
                    "AND json_extract(data,'$.ParentProcessGuid')=? ORDER BY ts LIMIT ?",
                    (agent_id, SYSMON, parent["guid"], MAX_CHILDREN + 1))
                for k in kids[:MAX_CHILDREN]:
                    if len(nodes) >= MAX_NODES:
                        break
                    n = self._node(k)
                    if n["guid"] in nodes:
                        continue
                    nodes[n["guid"]] = n
                    parent["children"].append(n)
                    nxt.append(n)
                if len(kids) > MAX_CHILDREN:
                    parent["more_children"] = True
            frontier = nxt

        # ancestors
        root, cur_ev = focus, ev
        for _ in range(MAX_UP):
            d = cur_ev["data"] if cur_ev else {}
            pguid = d.get("ParentProcessGuid")
            if not pguid or pguid in nodes:
                break
            pev = self._proc_event(agent_id, pguid)
            parent = self._node(pev) if pev else self._stub_parent(d)
            if not parent["name"] or parent["name"] == "-":
                break
            parent["children"].append(root)
            nodes[pguid] = parent
            root, cur_ev = parent, pev
            if not pev:
                break

        # activity + exits for every process in the tree
        guids = [g for g in nodes if g]
        marks = ",".join("?" * len(guids))
        acts = self._q(
            f"SELECT * FROM events WHERE agent_id=? AND channel=? AND event_id IN (3,22,11,12,13,10,8,5) "
            f"AND (json_extract(data,'$.ProcessGuid') IN ({marks}) OR json_extract(data,'$.SourceProcessGuid') IN ({marks})) "
            f"ORDER BY ts LIMIT 400", (agent_id, SYSMON, *guids, *guids))
        for a in acts:
            d = a["data"]
            owner = nodes.get(d.get("SourceProcessGuid") or d.get("ProcessGuid"))
            if not owner or owner.get("stub"):
                continue
            if a["event_id"] == 5:
                owner["exited"] = a["ts"]
                continue
            kind = ACTIVITY.get(a["event_id"])
            if kind == "access" and not d.get("TargetImage"):
                continue
            if len(owner["activity"]) < MAX_ACTIVITY:
                owner["activity"].append({"kind": kind, "summary": a["summary"], "ts": a["ts"], "id": a["id"],
                                          "event_id": a["event_id"]})
            else:
                owner["more_activity"] = owner.get("more_activity", 0) + 1

        return {"focus_guid": guid, "root": root, "count": len(nodes)}
