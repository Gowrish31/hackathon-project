"""
Detection engine: Sigma-style YAML rules evaluated against every normalized event.

Rule format (see rules/*.yml):
  id, title, description, severity (low|medium|high|critical)
  mitre: {tactic, technique, name}
  match:
    channel: sysmon | security | powershell | defender | system | <full channel name>
    event_id: 1 | [4720, 4722]
    where:   {Field|modifier: value | [values]}   all fields must match; a list means "any of"
    not:     {Field|modifier: value | [values]}   exclude if ANY of these match
  threshold: {count: 5, window: 60, group_by: [Field], distinct: Field}   optional
  alert: "Title template with {Field} placeholders"   optional
Modifiers: equals (default), contains, startswith, endswith, re. All case-insensitive.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

CHANNEL_ALIASES = {
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "security": "Security",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "defender": "Microsoft-Windows-Windows Defender/Operational",
    "system": "System",
    "canary": "Aegis/Canary",
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Fields copied onto the alert so the dashboard / responder can act on them
CONTEXT_FIELDS = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "ProcessId", "ProcessGuid",
                  "SourceImage", "SourceProcessId", "TargetImage", "TargetObject", "Details", "TargetFilename",
                  "TargetUserName", "SubjectUserName", "IpAddress", "TaskName", "ServiceName", "MemberName",
                  "ScriptBlockText", "QueryName", "DestinationIp", "DestinationPort",
                  # ransomware canary (agent-generated)
                  "CanaryFile", "Change", "Action", "Confidence", "TrippedAt", "KilledAt", "KillMs", "ProcessStartedAt",
                  "FilesAffected", "FilesScanned", "ScanRoot", "ScanTruncated", "BytesWritten", "Suspects", "Drill", "ImageName", "Headline"]


class _Cond:
    def __init__(self, key: str, value: Any):
        field, _, mod = key.partition("|")
        self.field = field
        self.mod = mod or "equals"
        vals = value if isinstance(value, list) else [value]
        self.values = [str(v).lower() for v in vals]
        if self.mod == "re":
            self.regex = [re.compile(v, re.I) for v in (value if isinstance(value, list) else [value])]
        elif self.mod not in ("equals", "contains", "startswith", "endswith"):
            raise ValueError(f"unknown modifier {self.mod}")

    def test(self, data: Dict[str, str]) -> bool:
        raw = data.get(self.field)
        if raw is None:
            return False
        raw = str(raw)
        if self.mod == "re":
            return any(r.search(raw) for r in self.regex)
        v = raw.lower()
        if self.mod == "equals":
            return v in self.values
        if self.mod == "contains":
            return any(x in v for x in self.values)
        if self.mod == "startswith":
            return any(v.startswith(x) for x in self.values)
        return any(v.endswith(x) for x in self.values)


class Rule:
    def __init__(self, spec: Dict[str, Any], source: str):
        self.id = spec["id"]
        self.title = spec["title"]
        self.description = spec.get("description", "")
        self.severity = spec.get("severity", "medium")
        self.mitre = spec.get("mitre", {})
        self.alert_template = spec.get("alert")
        self.source = source
        m = spec["match"]
        ch = m.get("channel")
        self.channel = CHANNEL_ALIASES.get(ch, ch) if ch else None
        eids = m.get("event_id")
        self.event_ids = set(eids if isinstance(eids, list) else [eids]) if eids is not None else None
        self.where = [_Cond(k, v) for k, v in (m.get("where") or {}).items()]
        self.exclude = [_Cond(k, v) for k, v in (m.get("not") or {}).items()]
        self.threshold = spec.get("threshold")

    def matches(self, ev: Dict[str, Any]) -> bool:
        if self.channel and ev["channel"] != self.channel:
            return False
        if self.event_ids is not None and ev["event_id"] not in self.event_ids:
            return False
        d = ev["data"]
        if not all(c.test(d) for c in self.where):
            return False
        return not any(c.test(d) for c in self.exclude)

    def public(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "description": self.description,
                "severity": self.severity, "mitre": self.mitre}


class _SafeDict(dict):
    def __missing__(self, key):
        return "?"


class DetectionEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules: List[Rule] = []
        self.windows: Dict[tuple, deque] = defaultdict(deque)  # (rule, agent, group) -> deque[(t, event)]
        self.cooldown: Dict[tuple, float] = {}
        self.load()

    def load(self) -> None:
        rules = []
        for f in sorted(self.rules_dir.glob("*.yml")):
            for spec in yaml.safe_load_all(f.read_text()):
                if spec:
                    rules.append(Rule(spec, f.name))
        self.rules = rules

    def _alert(self, rule: Rule, ev: Dict[str, Any], related: List[Dict[str, Any]]) -> Dict[str, Any]:
        d = ev["data"]
        title = rule.alert_template.format_map(_SafeDict(d, count=len(related))) if rule.alert_template else rule.title
        return {
            "rule_id": rule.id,
            "rule_title": rule.title,
            "title": title,
            "description": rule.description,
            "severity": rule.severity,
            "tactic": rule.mitre.get("tactic", ""),
            "technique": rule.mitre.get("technique", ""),
            "technique_name": rule.mitre.get("name", ""),
            "agent_id": ev["agent_id"],
            "hostname": ev["hostname"],
            "ts": ev["ts"],
            "event_ids": [e["id"] for e in related],
            "context": {k: d[k] for k in CONTEXT_FIELDS if d.get(k)},
        }

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        now = time.time()
        for ev in events:
            for rule in self.rules:
                if not rule.matches(ev):
                    continue
                th = rule.threshold
                if not th:
                    alerts.append(self._alert(rule, ev, [ev]))
                    continue
                group = tuple(str(ev["data"].get(f, "")) for f in th.get("group_by", []))
                key = (rule.id, ev["agent_id"], group)
                if self.cooldown.get(key, 0) > now:
                    continue
                win = self.windows[key]
                win.append((now, ev))
                while win and now - win[0][0] > th.get("window", 60):
                    win.popleft()
                related = [e for _, e in win]
                distinct = th.get("distinct")
                n = len({str(e["data"].get(distinct, "")).lower() for e in related}) if distinct else len(related)
                if n >= th.get("count", 5):
                    alerts.append(self._alert(rule, ev, related))
                    win.clear()
                    self.cooldown[key] = now + th.get("cooldown", th.get("window", 60))
        return alerts
