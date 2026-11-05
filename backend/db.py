"""SQLite storage. One connection + lock is plenty for a single-VM demo."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from normalize import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, os TEXT, user TEXT,
  agent_version TEXT, is_admin INTEGER, first_seen TEXT, last_seen TEXT, info TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT, hostname TEXT, ts TEXT, received_at TEXT,
  channel TEXT, provider TEXT, event_id INTEGER, record_id INTEGER,
  category TEXT, summary TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events(agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, type TEXT, args TEXT,
  status TEXT, created_at TEXT, completed_at TEXT, result TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT, rule_title TEXT, title TEXT, description TEXT, severity TEXT,
  tactic TEXT, technique TEXT, technique_name TEXT,
  agent_id TEXT, hostname TEXT, ts TEXT, created_at TEXT,
  status TEXT DEFAULT 'open', event_ids TEXT, context TEXT, analysis TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


def _agent_row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["is_admin"] = bool(d["is_admin"])
    d["info"] = json.loads(d["info"] or "{}")
    return d


def _event_row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["data"] = json.loads(d["data"] or "{}")
    return d


def _alert_row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["event_ids"] = json.loads(d["event_ids"] or "[]")
    d["context"] = json.loads(d["context"] or "{}")
    d["analysis"] = json.loads(d["analysis"]) if d["analysis"] else None
    return d


def _cmd_row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["args"] = json.loads(d["args"] or "{}")
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(commands)")}
        if "sent_at" not in cols:  # migration: when the agent picked the command up
            self.conn.execute("ALTER TABLE commands ADD COLUMN sent_at TEXT")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_pguid ON events(json_extract(data,'$.ProcessGuid'))")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ppguid ON events(json_extract(data,'$.ParentProcessGuid'))")
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- agents
    def upsert_agent(self, hb: Dict[str, Any]) -> Dict[str, Any]:
        now = now_iso()
        info = {k: v for k, v in hb.items() if k not in ("agent_id", "hostname", "ip", "os", "user", "agent_version", "is_admin")}
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO agents (id, hostname, ip, os, user, agent_version, is_admin, first_seen, last_seen, info)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname, ip=excluded.ip, os=excluded.os,
                     user=excluded.user, agent_version=excluded.agent_version, is_admin=excluded.is_admin,
                     last_seen=excluded.last_seen, info=excluded.info""",
                (hb["agent_id"], hb.get("hostname"), hb.get("ip"), hb.get("os"), hb.get("user"),
                 hb.get("agent_version"), int(bool(hb.get("is_admin"))), now, now, json.dumps(info)),
            )
            row = self.conn.execute("SELECT * FROM agents WHERE id=?", (hb["agent_id"],)).fetchone()
        return _agent_row(row)

    def list_agents(self) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        return [_agent_row(r) for r in rows]

    # ---------------------------------------------------------------- events
    def insert_events(self, agent_id: str, hostname: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = now_iso()
        out = []
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO agents (id, hostname, first_seen, last_seen, is_admin, info) VALUES (?,?,?,?,0,'{}') "
                "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
                (agent_id, hostname, now, now),
            )
            for e in events:
                cur = self.conn.execute(
                    """INSERT INTO events (agent_id, hostname, ts, received_at, channel, provider, event_id,
                       record_id, category, summary, data) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (agent_id, hostname, e["ts"], now, e["channel"], e["provider"], e["event_id"],
                     e["record_id"], e["category"], e["summary"], json.dumps(e["data"])),
                )
                out.append({"id": cur.lastrowid, "agent_id": agent_id, "hostname": hostname, "received_at": now, **e})
        return out

    def list_events(self, limit: int = 200, agent_id: Optional[str] = None, category: Optional[str] = None,
                    q: Optional[str] = None, before_id: Optional[int] = None) -> List[Dict[str, Any]]:
        where, args = [], []
        if agent_id:
            where.append("agent_id=?"); args.append(agent_id)
        if category:
            where.append("category=?"); args.append(category)
        if q:
            where.append("(summary LIKE ? OR data LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
        if before_id:
            where.append("id<?"); args.append(before_id)
        sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(limit, 5000)))
        with self.lock:
            rows = self.conn.execute(sql, args).fetchall()
        return [_event_row(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            cats = self.conn.execute("SELECT category, COUNT(*) c FROM events GROUP BY category ORDER BY c DESC").fetchall()
            sev = self.conn.execute(
                "SELECT severity, COUNT(*) c FROM alerts WHERE status IN ('open','acknowledged') GROUP BY severity").fetchall()
        return {"total_events": total, "by_category": {r["category"]: r["c"] for r in cats},
                "open_alerts": {r["severity"]: r["c"] for r in sev}}

    # ---------------------------------------------------------------- alerts
    ALERT_COLS = ("rule_id", "rule_title", "title", "description", "severity", "tactic", "technique",
                  "technique_name", "agent_id", "hostname", "ts")

    def insert_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        now = now_iso()
        with self.lock, self.conn:
            for a in alerts:
                cur = self.conn.execute(
                    f"INSERT INTO alerts ({','.join(self.ALERT_COLS)}, created_at, status, event_ids, context) "
                    f"VALUES ({','.join('?' * len(self.ALERT_COLS))},?,'open',?,?)",
                    [a[c] for c in self.ALERT_COLS] + [now, json.dumps(a["event_ids"]), json.dumps(a["context"])])
                out.append(_alert_row(self.conn.execute("SELECT * FROM alerts WHERE id=?", (cur.lastrowid,)).fetchone()))
        return out

    def list_alerts(self, limit: int = 200, status: Optional[str] = None, agent_id: Optional[str] = None,
                    severity: Optional[str] = None) -> List[Dict[str, Any]]:
        where, args = [], []
        for col, val in (("status", status), ("agent_id", agent_id), ("severity", severity)):
            if val:
                where.append(f"{col}=?"); args.append(val)
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(limit, 2000)))
        with self.lock:
            rows = self.conn.execute(sql, args).fetchall()
        return [_alert_row(r) for r in rows]

    def get_alert(self, aid: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return _alert_row(row) if row else None

    def update_alert(self, aid: int, status: Optional[str] = None, analysis: Any = None) -> Optional[Dict[str, Any]]:
        with self.lock, self.conn:
            if status:
                self.conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, aid))
            if analysis is not None:
                self.conn.execute("UPDATE alerts SET analysis=? WHERE id=?", (json.dumps(analysis), aid))
            row = self.conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return _alert_row(row) if row else None

    def events_by_ids(self, ids: List[int]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        with self.lock:
            rows = self.conn.execute(
                f"SELECT * FROM events WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts", ids).fetchall()
        return [_event_row(r) for r in rows]

    # ---------------------------------------------------------------- commands
    def add_command(self, agent_id: str, ctype: str, args: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO commands (agent_id, type, args, status, created_at) VALUES (?,?,?,'pending',?)",
                (agent_id, ctype, json.dumps(args), now_iso()),
            )
            row = self.conn.execute("SELECT * FROM commands WHERE id=?", (cur.lastrowid,)).fetchone()
        return _cmd_row(row)

    SENT_TIMEOUT_S = 150  # longest command (isolation firewall script) is ~60 s; an agent that died mid-command never answers

    def _expire_sent(self, agent_id: str) -> None:
        """Caller holds the lock. A command the agent picked up but never answered would otherwise spin forever."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=self.SENT_TIMEOUT_S)).strftime("%Y-%m-%dT%H:%M:%S")
        self.conn.execute(
            "UPDATE commands SET status='failed', completed_at=?, result=? WHERE agent_id=? AND status='sent' AND sent_at<?",
            (now_iso(), json.dumps({"error": "the agent picked this up but never reported back"}), agent_id, cutoff))

    def take_pending(self, agent_id: str, max_age_s: int = 60) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_s)).strftime("%Y-%m-%dT%H:%M:%S")
        with self.lock, self.conn:
            self._expire_sent(agent_id)
            # a kill queued minutes ago must not fire later against a recycled PID
            self.conn.execute(
                "UPDATE commands SET status='expired', completed_at=? WHERE agent_id=? AND status='pending' AND created_at<?",
                (now_iso(), agent_id, cutoff))
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE agent_id=? AND status='pending' ORDER BY id", (agent_id,)).fetchall()
            sent_at = now_iso()
            if rows:
                self.conn.execute(
                    f"UPDATE commands SET status='sent', sent_at=? WHERE id IN ({','.join('?' * len(rows))})",
                    [sent_at, *[r["id"] for r in rows]])
        return [_cmd_row(r) | {"status": "sent", "sent_at": sent_at} for r in rows]

    def complete_command(self, cid: int, status: str, result: Any) -> Optional[Dict[str, Any]]:
        with self.lock, self.conn:
            self.conn.execute("UPDATE commands SET status=?, result=?, completed_at=? WHERE id=?",
                              (status, json.dumps(result), now_iso(), cid))
            row = self.conn.execute("SELECT * FROM commands WHERE id=?", (cid,)).fetchone()
        return _cmd_row(row) if row else None

    def commands_for_alert(self, aid: int) -> List[Dict[str, Any]]:
        """Response actions for an alert: tagged with its id, or a kill of its process sent after it fired."""
        with self.lock:
            a = self.conn.execute("SELECT agent_id, ts, context FROM alerts WHERE id=?", (aid,)).fetchone()
            if not a:
                return []
            ctx = json.loads(a["context"] or "{}")
            pid = ctx.get("ProcessId") or ctx.get("SourceProcessId")
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE json_extract(args,'$.alert_id')=? "
                "OR (agent_id=? AND type='kill_process' AND json_extract(args,'$.alert_id') IS NULL "
                "    AND CAST(json_extract(args,'$.pid') AS TEXT)=? AND created_at>=?) ORDER BY id",
                (aid, a["agent_id"], str(pid), a["ts"])).fetchall()
        return [_cmd_row(r) for r in rows]

    def response_summary(self) -> Dict[str, Any]:
        """Successful process kills and how long each took from click to confirmation."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT created_at, completed_at FROM commands WHERE type='kill_process' AND status='done'").fetchall()
        secs = []
        for r in rows:
            try:
                a = datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
                b = datetime.fromisoformat(r["completed_at"].replace("Z", "+00:00"))
                secs.append((b - a).total_seconds())
            except (TypeError, ValueError):
                pass
        return {"stopped": len(rows), "avg_s": round(sum(secs) / len(secs), 2) if secs else None,
                "fastest_s": round(min(secs), 2) if secs else None}

    def list_commands(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock, self.conn:
            self._expire_sent(agent_id)
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE agent_id=? ORDER BY id DESC LIMIT ?", (agent_id, limit)).fetchall()
        return [_cmd_row(r) for r in rows]
