"""Turns raw Windows events from the agent into categorised events with a one-line summary."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
SYSTEM = "System"
CANARY = "Aegis/Canary"


def now_iso() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_ts(s: str | None) -> datetime | None:
    """Parse a Windows UTC timestamp (up to 7 fractional digits)."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", s or "")
    if not m:
        return None
    dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return dt.replace(microsecond=int((m.group(2) or "0")[:6].ljust(6, "0")))


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def norm_ts(s: str | None, skew: timedelta = timedelta(0)) -> str:
    """Sortable millisecond UTC string, corrected for the endpoint's clock skew."""
    dt = parse_ts(s)
    return fmt_ts(dt + skew) if dt else now_iso()


def base(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1] or "?"


def _user(d: Dict[str, str]) -> str:
    dom, usr = d.get("TargetDomainName", ""), d.get("TargetUserName", "")
    return f"{dom}\\{usr}" if dom and dom != "-" else usr or "?"


def classify(channel: str, eid: int, d: Dict[str, str]) -> Tuple[str, str]:
    """Return (category, summary)."""
    if channel == SYSMON:
        img = base(d.get("Image"))
        if eid == 1:
            return "process", f"{img} started by {base(d.get('ParentImage'))}: {d.get('CommandLine', '')}"
        if eid == 3:
            dst = d.get("DestinationHostname") if d.get("DestinationHostname") not in (None, "", "-") else d.get("DestinationIp", "?")
            return "network", f"{img} -> {dst}:{d.get('DestinationPort', '?')} ({d.get('Protocol', '')})"
        if eid == 5:
            return "process", f"{img} exited"
        if eid == 6:
            return "system", f"driver loaded: {d.get('ImageLoaded', '')}"
        if eid == 7:
            return "process", f"{img} loaded {base(d.get('ImageLoaded'))}"
        if eid == 8:
            return "injection", f"{base(d.get('SourceImage'))} created remote thread in {base(d.get('TargetImage'))}"
        if eid == 10:
            return "injection", f"{base(d.get('SourceImage'))} accessed {base(d.get('TargetImage'))} (access {d.get('GrantedAccess', '?')})"
        if eid in (11, 15):
            return "file", f"{img} created {d.get('TargetFilename', '')}"
        if eid in (12, 13, 14):
            det = f" = {d.get('Details')}" if d.get("Details") else ""
            return "registry", f"{img} {d.get('EventType', 'modified')} {d.get('TargetObject', '')}{det}"
        if eid in (17, 18):
            return "process", f"{img} pipe {d.get('PipeName', '')}"
        if eid == 22:
            return "dns", f"{img} resolved {d.get('QueryName', '')}"
        if eid in (23, 26):
            return "file", f"{img} deleted {d.get('TargetFilename', '')}"
        if eid in (4, 16, 25):
            return "tamper", f"Sysmon state/config change (event {eid})"
        return "other", f"Sysmon event {eid}"

    if channel == SECURITY:
        if eid == 4624:
            return "auth", f"logon success {_user(d)} (type {d.get('LogonType')}) from {d.get('IpAddress', '-')}"
        if eid == 4625:
            return "auth", f"logon FAILED ({d.get('Reason', '?')}) for {d.get('Account', _user(d))} from {d.get('Source', d.get('IpAddress', '-'))}"
        if eid == 4648:
            return "auth", f"explicit credentials used for {_user(d)} by {base(d.get('ProcessName'))}"
        if eid == 4672:
            return "auth", f"privileged logon {d.get('SubjectUserName', '?')}"
        if eid == 4740:
            return "auth", f"account locked out: {d.get('TargetUserName', '?')}"
        if eid == 4688:
            return "process", f"{base(d.get('NewProcessName'))} started by {base(d.get('ParentProcessName'))}: {d.get('CommandLine', '')}"
        if eid in (4697,):
            return "persistence", f"service installed: {d.get('ServiceName', '?')} ({d.get('ServiceFileName', '')})"
        if eid in (4698, 4699, 4702):
            verb = {4698: "created", 4699: "deleted", 4702: "updated"}[eid]
            return "persistence", f"scheduled task {verb}: {d.get('TaskName', '?')} by {d.get('SubjectUserName', '?')}"
        if eid == 4719:
            return "tamper", f"audit policy changed by {d.get('SubjectUserName', '?')}"
        if eid in (4720, 4722, 4724, 4726, 4738):
            verb = {4720: "created", 4722: "enabled", 4724: "password reset", 4726: "deleted", 4738: "changed"}[eid]
            return "account", f"user account {verb}: {d.get('TargetUserName', '?')} by {d.get('SubjectUserName', '?')}"
        if eid in (4728, 4732, 4756):
            return "account", f"{d.get('MemberName') or d.get('MemberSid', '?')} added to group {d.get('TargetUserName', '?')}"
        if eid == 1102:
            return "tamper", f"Security log CLEARED by {d.get('SubjectUserName', '?')}"
        return "auth", f"Security event {eid}"

    if channel == POWERSHELL and eid == 4104:
        text = (d.get("ScriptBlockText") or "").strip().replace("\r", " ").replace("\n", " ")
        return "script", f"PowerShell script block: {text[:300]}"

    if channel == DEFENDER:
        if eid in (1116, 1117):
            return "av", f"Defender {'detected' if eid == 1116 else 'acted on'} {d.get('Threat Name', '?')} ({d.get('Path', '')})"
        if eid == 5001:
            return "tamper", "Defender real-time protection DISABLED"

    if channel == SYSTEM:
        if eid == 7045:
            return "persistence", f"service installed: {d.get('ServiceName', '?')} ({d.get('ImagePath', '')})"
        if eid == 104:
            return "tamper", f"event log cleared: {d.get('Channel', '?')}"

    if channel == CANARY:
        who = f"{base(d.get('Image')) or 'an unidentified process'}" + (f" (PID {d['ProcessId']})" if d.get("ProcessId") else "")
        return "ransomware", (f"Ransomware canary {base(d.get('CanaryFile'))} {d.get('Change', 'changed')} by {who}; "
                              f"{d.get('Action', '?')}, {d.get('FilesAffected', '?')} files hit")

    return "other", f"{channel} event {eid}"


# Windows logon failure codes (4625 SubStatus, or Status when SubStatus is 0)
LOGON_FAILURE = {
    "0xc000006a": "wrong password",
    "0xc0000380": "wrong PIN",
    "0xc0000064": "unknown user name",
    "0xc0000234": "account locked out",
    "0xc0000072": "account disabled",
    "0xc0000193": "account expired",
    "0xc0000071": "password expired",
    "0xc0000224": "password must change",
    "0xc000006f": "outside allowed hours",
    "0xc0000070": "workstation not allowed",
    "0xc000015b": "logon type not allowed",
    "0xc000006d": "bad user name or password",
}
LOCAL_SOURCES = {"", "-", "127.0.0.1", "::1"}


def _enrich_logon_failure(d: Dict[str, str]) -> None:
    """Adds readable fields to a 4625: Reason, Account and Source (used by the summary and alert text)."""
    sub, st = d.get("SubStatus", "").lower(), d.get("Status", "").lower()
    d["Reason"] = LOGON_FAILURE.get(sub) or LOGON_FAILURE.get(st) or f"failure {sub or st or 'unknown'}"
    usr = d.get("TargetUserName", "")
    if usr and usr != "-":
        dom = d.get("TargetDomainName", "")
        d["Account"] = f"{dom}\\{usr}" if dom and dom != "-" else usr
    else:  # a failed Windows Hello PIN does not name the account
        host = d.get("WorkstationName") if d.get("WorkstationName") not in ("", "-") else d.get("SubjectUserName", "").rstrip("$")
        d["Account"] = f"a user on {host}" if host else "an unnamed account"
    ip = d.get("IpAddress", "")
    d["Source"] = "the local sign-in screen" if ip in LOCAL_SOURCES else ip


def normalize(raw: Dict[str, Any], skew: timedelta = timedelta(0)) -> Dict[str, Any]:
    data = {k: ("" if v is None else str(v)) for k, v in (raw.get("data") or {}).items()}
    channel = raw.get("channel") or ""
    eid = int(raw.get("event_id") or 0)
    if channel == SECURITY and eid == 4625:
        _enrich_logon_failure(data)
    if channel == CANARY:
        name = base(data["Image"]) if data.get("Image") else "an unidentified process"
        data["ImageName"] = name
        data["Headline"] = (f"Ransomware stopped: {name} killed after encrypting {data.get('FilesAffected', '?')} files"
                            if data.get("Action") == "killed" else
                            f"Ransomware canary tripped by {name}: {data.get('Action', 'no action taken')}")
    category, summary = classify(channel, eid, data)
    return {
        "ts": norm_ts(raw.get("ts"), skew),
        "channel": channel,
        "provider": raw.get("provider") or "",
        "event_id": eid,
        "record_id": raw.get("record_id"),
        "category": category,
        "summary": summary[:1000],
        "data": data,
    }


def estimate_skew(sent_at: str | None, event_ts: list) -> timedelta:
    """How far behind the endpoint clock is. Prefer the agent's sent_at; otherwise assume the
    newest event in the batch happened ~now (only trusted for large skews, e.g. a wrong VM clock)."""
    now = datetime.now(timezone.utc)
    sent = parse_ts(sent_at)
    if sent:
        skew = now - sent
        return skew if abs(skew) > timedelta(seconds=2) else timedelta(0)
    times = [t for t in (parse_ts(x) for x in event_ts) if t]
    if times:
        skew = now - max(times)
        return skew if abs(skew) > timedelta(minutes=5) else timedelta(0)
    return timedelta(0)
