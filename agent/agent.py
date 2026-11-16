"""
Aegis endpoint agent (Windows).

Subscribes to Sysmon / Security / PowerShell / Defender / System event logs,
ships events to the Aegis backend in batches, sends heartbeats, and executes
response commands queued from the dashboard.

Standard library only: the event log is read through wevtapi.dll with ctypes, so
the agent runs on the embeddable Python that the one-line installer drops in
C:\\Program Files\\Aegis. No pip, no pywin32.

Installed (normal):   the "Aegis Agent" scheduled task runs   pythonw agent.py --service
Manual (lab VM):      python agent.py --server http://<backend-ip>:8000 -v
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from ctypes import wintypes
from typing import Any, Dict, List, Optional

if os.name != "nt":  # pragma: no cover
    sys.exit("The Aegis agent only runs on Windows.")

AGENT_VERSION = "0.4.6"
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
TASK_NAME = "Aegis Agent"
EXIT_RESTART = 3  # worker exit code that asks the supervisor to start it again (after an update)
log = logging.getLogger("aegis-agent")

# channel -> list of event IDs to collect (None = everything)
CHANNELS: Dict[str, Optional[List[int]]] = {
    "Microsoft-Windows-Sysmon/Operational": None,
    "Security": [
        1102,  # audit log cleared
        4624, 4625, 4648, 4672, 4740,  # logons / failures / explicit creds / lockout
        4697, 4698, 4699, 4702,  # service install, scheduled tasks
        4719,  # audit policy changed
        4720, 4722, 4724, 4726, 4738,  # user account changes
        4728, 4732, 4756,  # added to privileged groups
    ],
    "Microsoft-Windows-PowerShell/Operational": [4104],  # script block logging
    "Microsoft-Windows-Windows Defender/Operational": [1116, 1117, 5001],
    "System": [104, 7045],  # log cleared, new service
}

ISOLATION_GROUP = "Aegis Isolation"
ISOLATION_STATE = os.path.join(HERE, "isolation.json")
ISOLATION_FAILSAFE_MIN = 15  # demo safety: lift isolation if the console is unreachable this long (0 = never)

# While isolated, DNS is blocked too, so the console's hostname is pinned to the IPs it had
# when isolation started. Every request the agent makes resolves through this.
PINNED_HOSTS: Dict[str, List[str]] = {}
_real_getaddrinfo = socket.getaddrinfo


def _pinned_getaddrinfo(host, *args, **kwargs):
    ips = PINNED_HOSTS.get(host) if isinstance(host, str) else None
    if ips:
        err: Optional[Exception] = None
        for ip in ips:
            try:
                return _real_getaddrinfo(ip, *args, **kwargs)
            except OSError as e:
                err = e
        raise err  # type: ignore[misc]
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _pinned_getaddrinfo

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSTEM_SID = "S-1-5-18"


# --------------------------------------------------------------------------- wevtapi via ctypes
wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
EVT_HANDLE = ctypes.c_void_p
EVT_SUBSCRIBE_TO_FUTURE = 1
EVT_RENDER_XML = 1
EVT_ACTION_ERROR, EVT_ACTION_DELIVER = 0, 1
ERROR_INSUFFICIENT_BUFFER = 122
# DWORD WINAPI callback(EVT_SUBSCRIBE_NOTIFY_ACTION, PVOID context, EVT_HANDLE event)
EVT_CALLBACK = ctypes.WINFUNCTYPE(wintypes.DWORD, ctypes.c_int, ctypes.c_void_p, EVT_HANDLE)

wevtapi.EvtSubscribe.argtypes = [EVT_HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                 EVT_HANDLE, ctypes.c_void_p, EVT_CALLBACK, wintypes.DWORD]
wevtapi.EvtSubscribe.restype = EVT_HANDLE
wevtapi.EvtRender.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
wevtapi.EvtRender.restype = wintypes.BOOL
wevtapi.EvtClose.argtypes = [EVT_HANDLE]
wevtapi.EvtClose.restype = wintypes.BOOL


def render_xml(handle: int) -> str:
    used, count = wintypes.DWORD(0), wintypes.DWORD(0)
    if not wevtapi.EvtRender(None, handle, EVT_RENDER_XML, 0, None, ctypes.byref(used), ctypes.byref(count)):
        err = ctypes.get_last_error()
        if err != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(err)
    buf = ctypes.create_unicode_buffer(used.value // ctypes.sizeof(ctypes.c_wchar) + 1)
    if not wevtapi.EvtRender(None, handle, EVT_RENDER_XML, ctypes.sizeof(buf), buf,
                             ctypes.byref(used), ctypes.byref(count)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.value


# --------------------------------------------------------------------------- helpers
def xpath_for(ids: Optional[List[int]]) -> str:
    if not ids:
        return "*"
    return "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1]


def parse_event_xml(xml: str) -> Optional[Dict[str, Any]]:
    root = ET.fromstring(xml)
    sysnode = root.find("e:System", NS)
    if sysnode is None:
        return None
    eid = sysnode.find("e:EventID", NS)
    tc = sysnode.find("e:TimeCreated", NS)
    prov = sysnode.find("e:Provider", NS)
    rec = sysnode.find("e:EventRecordID", NS)
    chan = sysnode.find("e:Channel", NS)

    data: Dict[str, str] = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for i, d in enumerate(ed.findall("e:Data", NS)):
            data[d.get("Name") or f"Data{i}"] = d.text or ""
    ud = root.find("e:UserData", NS)
    if ud is not None:
        for el in ud.iter():
            if len(el) == 0 and el.text and el.text.strip():
                data[local_name(el.tag)] = el.text.strip()
    # PowerShell script-block events carry no process fields; keep the host PID so the
    # backend can tie the script to its powershell.exe in the process tree.
    exe = sysnode.find("e:Execution", NS)
    if exe is not None and exe.get("ProcessID") and chan is not None and "PowerShell" in (chan.text or ""):
        data["ExecutionProcessID"] = exe.get("ProcessID")

    return {
        "ts": tc.get("SystemTime") if tc is not None else None,
        "channel": chan.text if chan is not None else "",
        "provider": prov.get("Name") if prov is not None else "",
        "event_id": int(eid.text) if eid is not None and eid.text else 0,
        "record_id": int(rec.text) if rec is not None and rec.text else None,
        "data": data,
    }


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_user() -> str:
    """The person signed in at the console. Under the service this process runs as SYSTEM.

    Asked through WTS rather than `query user`/PowerShell so the agent spawns no processes
    (which would show up in its own telemetry) and it works on Home editions too.
    """
    try:
        wts = ctypes.WinDLL("wtsapi32")
        session = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        if session != 0xFFFFFFFF:
            buf, size = wintypes.LPWSTR(), wintypes.DWORD()
            if wts.WTSQuerySessionInformationW(None, session, 5, ctypes.byref(buf), ctypes.byref(size)):  # 5 = WTSUserName
                name = buf.value
                wts.WTSFreeMemory(buf)
                if name:
                    return name
    except Exception:
        pass
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def local_ip_towards(server_url: str) -> str:
    host = server_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


def os_name() -> str:
    """platform.release() says "10" on Windows 11; the build number tells them apart."""
    try:
        build = int(platform.version().split(".")[2])
    except Exception:
        build = 0
    name = "Windows 11" if build >= 22000 else f"{platform.system()} {platform.release()}"
    return f"{name} ({platform.win32_edition()})" if hasattr(platform, "win32_edition") and platform.win32_edition() else name


def run_ps(script: str, timeout: float = 60) -> str:
    out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-Command", "$ErrorActionPreference='Stop'; " + script],
                         capture_output=True, text=True, timeout=timeout,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if out.returncode != 0:
        msg = (out.stderr or out.stdout or "").strip()
        raise RuntimeError((msg or f"powershell exited with code {out.returncode} and no output")[:600])
    return out.stdout.strip()


def tcp_probe(host: str, port: int, timeout: float = 3) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def isolation_load() -> Optional[Dict[str, Any]]:
    try:
        with open(ISOLATION_STATE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def isolation_save(state: Dict[str, Any]) -> None:
    with open(ISOLATION_STATE + ".new", "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(ISOLATION_STATE + ".new", ISOLATION_STATE)


def address_ranges_except(keep: List[str]) -> List[str]:
    """Every IPv4 and IPv6 address as ranges, minus the ones in `keep`."""
    out: List[str] = []
    # Range endpoints must be ordinary unicast: Windows Firewall rejects a range that starts or ends
    # on ::, ::1 (loopback) or ff00::/8 (multicast). IPv6 multicast is left out of the block; it never
    # leaves the local link anyway.
    for version, cls, lo, hi in ((4, ipaddress.IPv4Address, 1, 2 ** 32 - 1),
                                 (6, ipaddress.IPv6Address, 2, int(ipaddress.IPv6Address("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))):
        start = lo
        for k in sorted(int(ipaddress.ip_address(i)) for i in keep if ipaddress.ip_address(i).version == version):
            if k > start:
                out.append(f"{cls(start)}-{cls(k - 1)}")
            start = max(start, k + 1)
        if start <= hi:
            out.append(f"{cls(start)}-{cls(hi)}")
    return out


def isolation_rules_script(console_ips: List[str]) -> str:
    ra = ",".join(f"'{r}'" for r in address_ranges_except(console_ips))
    g = ISOLATION_GROUP
    rule = (f"New-NetFirewallRule -Group '{g}' -Profile Any -Action Block -RemoteAddress @({ra}) "
            "-DisplayName '{name}' -Direction {dir} -Protocol {proto} {extra} | Out-Null")
    rules = [
        ("Aegis isolation: outbound TCP", "Outbound", "TCP", ""),
        ("Aegis isolation: outbound UDP (DHCP kept)", "Outbound", "UDP", "-RemotePort '1-66','68-65535'"),
        ("Aegis isolation: outbound ICMPv4", "Outbound", "ICMPv4", ""),
        ("Aegis isolation: outbound ICMPv6", "Outbound", "ICMPv6", ""),
        ("Aegis isolation: inbound TCP", "Inbound", "TCP", ""),
        ("Aegis isolation: inbound UDP (DHCP kept)", "Inbound", "UDP", "-LocalPort '1-67','69-65535'"),
        ("Aegis isolation: inbound ICMPv4", "Inbound", "ICMPv4", ""),
        ("Aegis isolation: inbound ICMPv6", "Inbound", "ICMPv6", ""),
    ]
    lines = [f"Remove-NetFirewallRule -Group '{g}' -ErrorAction SilentlyContinue",
             "Set-NetFirewallProfile -All -Enabled True"]  # rules only bite with the firewall on
    lines += [rule.format(name=n, dir=d, proto=p, extra=x) for n, d, p, x in rules]
    return "; ".join(lines)


# --------------------------------------------------------------------------- ransomware canaries
# Decoy documents that no person or program has a reason to touch. A process that rewrites,
# renames or deletes one is treated as ransomware: the agent kills it on the spot (no round
# trip to the console) and reports what it hit. Attribution is by per-process write volume,
# which needs no driver and no Sysmon FileCreate coverage of the decoy folders.
CANARY_DIRNAME = "!Records"
CANARY_FILES = [("Accounts-2025.xlsx", b"PK\x03\x04"), ("Contracts-signed.docx", b"PK\x03\x04"),
                ("Passport-scan.pdf", b"%PDF-1.7\n"), ("Family-2024.jpg", b"\xff\xd8\xff\xe0")]
CANARY_CHANNEL = "Aegis/Canary"
CANARY_COOLDOWN_S = 10
DRILL_DIR = os.path.join(os.environ.get("PUBLIC") or r"C:\Users\Public", "Documents", "Aegis Ransomware Drill")
DRILL_CANARIES = [("Expense-Forecast-2026.xlsx", b"PK\x03\x04"), ("Payroll-Master.xlsx", b"PK\x03\x04")]
DRILL_GROUPS = [("Board-Minutes", ".docx", b"PK\x03\x04"), ("Client-Contract", ".pdf", b"%PDF-1.7\n"),
                ("Expense-Report", ".xlsx", b"PK\x03\x04"), ("Invoice", ".pdf", b"%PDF-1.7\n"),
                ("Payroll", ".xlsx", b"PK\x03\x04"), ("Tax-Return", ".pdf", b"%PDF-1.7\n"),
                ("Vendor-Quote", ".docx", b"PK\x03\x04")]
DRILL_EXT = ".aegislocked"
# The drill "encrypts" like LockBit-style intermittent encryption: XOR the first 4 KB, write the
# whole file under a new extension, delete the original. It only ever touches DRILL_DIR.
DRILL_SCRIPT = (
    "$target='" + DRILL_DIR.replace("'", "''") + "'; $key=0x5A; "
    "Get-ChildItem -LiteralPath $target -File | Where-Object { $_.Extension -ne '" + DRILL_EXT + "' } | "
    "Sort-Object Name | ForEach-Object { "
    "$bytes=[IO.File]::ReadAllBytes($_.FullName); "
    "for($i=0; $i -lt [Math]::Min(4096,$bytes.Length); $i++){ $bytes[$i]=$bytes[$i] -bxor $key }; "
    "[IO.File]::WriteAllBytes($_.FullName+'" + DRILL_EXT + "',$bytes); "
    "Remove-Item -LiteralPath $_.FullName -Force; Start-Sleep -Milliseconds 40 }; "
    "Set-Content -LiteralPath (Join-Path $target 'HOW-TO-RESTORE.txt') "
    "-Value 'Your files were encrypted. (Aegis drill: nothing real was harmed.)'"
)
# never auto-killed: killing these would crash Windows or blind the AV
PROTECTED_IMAGES = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
                    "winlogon.exe", "svchost.exe", "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe",
                    "searchindexer.exe", "dwm.exe", "fontdrvhost.exe", "audiodg.exe", "memory compression",
                    "sysmon.exe", "sysmon64.exe", "sysmona64.exe", "mssense.exe", "tiworker.exe",
                    "trustedinstaller.exe"}

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION = 0x0001, 0x1000


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                   "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO_COUNTERS)]
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD)]
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]


def list_pids() -> List[int]:
    arr = (wintypes.DWORD * 8192)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        return []
    return [arr[i] for i in range(needed.value // ctypes.sizeof(wintypes.DWORD)) if arr[i]]


def io_snapshot() -> Dict[int, tuple]:
    """pid -> (bytes read, bytes written) over the process lifetime."""
    out: Dict[int, tuple] = {}
    io = IO_COUNTERS()
    for pid in list_pids():
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            continue
        try:
            if kernel32.GetProcessIoCounters(h, ctypes.byref(io)):
                out[pid] = (io.ReadTransferCount, io.WriteTransferCount)
        finally:
            kernel32.CloseHandle(h)
    return out


def proc_info(pid: int) -> Dict[str, Any]:
    """Image path and start time (epoch seconds) of a running process."""
    info: Dict[str, Any] = {"image": "", "started": None}
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return info
    try:
        buf, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            info["image"] = buf.value
        times = [wintypes.FILETIME() for _ in range(4)]
        if kernel32.GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
            ft = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            info["started"] = (ft - 116444736000000000) / 1e7
    finally:
        kernel32.CloseHandle(h)
    return info


def terminate(pid: int) -> bool:
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(kernel32.TerminateProcess(h, 1))
    finally:
        kernel32.CloseHandle(h)


def write_decoy(path: str, magic: bytes, size: int = 48 * 1024) -> None:
    with open(path, "wb") as f:
        f.write(magic + os.urandom(size - len(magic)))


CHURN_WINDOW_S = 0.4
CHURN_WINDOWS = 3
CHURN_MIN_BYTES = 16 * 1024


def dir_state(dirs: List[str], cap: int = 5000) -> Dict[str, tuple]:
    """path -> (size, mtime_ns) for the files directly in `dirs`."""
    out: Dict[str, tuple] = {}
    for d in dirs:
        try:
            with os.scandir(d) as it:
                for i, e in enumerate(it):
                    if i >= cap:
                        break
                    try:
                        if e.is_file(follow_symlinks=False):
                            st = e.stat()
                            out[e.path] = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        pass
        except OSError:
            pass
    return out


def churn(before: Dict[str, tuple], after: Dict[str, tuple]) -> tuple:
    """(bytes an encryptor had to read, bytes it had to write) to turn `before` into `after`."""
    wrote = sum(sz for p, (sz, m) in after.items() if before.get(p) != (sz, m))
    read = sum(sz for p, (sz, m) in before.items() if after.get(p) != (sz, m))
    return read, wrote


def file_sig(path: str) -> Optional[tuple]:
    try:
        st = os.stat(path)
        return (st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def iso_utc(t: Optional[float] = None) -> str:
    t = time.time() if t is None else t
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


def count_damage(root: str, since: float, locked_ext: Optional[str] = None, budget_s: float = 2.0) -> Dict[str, Any]:
    """Files under `root` written or created since `since` (the attacker's start time).
    No slack before `since`: file and process times come from the same clock, and a slack window
    used to swallow files written just before the attacker started (the drill seeds its 142 files
    a split second before it launches the encryptor, so every one of them counted as encrypted).
    `locked_ext` (drills): count the files the encryptor actually produced - exact, not inferred."""
    changed = total = 0
    truncated = False
    t0 = time.time()
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            total += 1
            try:
                st = os.stat(os.path.join(dirpath, name))
            except OSError:
                continue
            if locked_ext:
                if name.lower().endswith(locked_ext):
                    changed += 1
            elif max(st.st_mtime, st.st_ctime) >= since:
                changed += 1
        if time.time() - t0 > budget_s:
            truncated = True
            break
    return {"changed": changed, "total": total, "truncated": truncated}


def load_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_PATH, encoding="utf-8-sig") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


# --------------------------------------------------------------------------- local owner portal
OWNER_PORT = 8765


class OwnerPortal:
    """A small loopback-only owner view.

    It deliberately binds to 127.0.0.1: a browser on another laptop cannot reach it.
    The agent, not the browser, uses its private enrollment key to retrieve this device's
    state from the console, so no reusable cloud URL or credential is exposed.
    """
    def __init__(self, agent: "Agent") -> None:
        self.agent = agent
        self.httpd: Optional[ThreadingHTTPServer] = None

    @property
    def page_path(self) -> str:
        return os.path.join(HERE, "device.html")

    def _page(self) -> bytes:
        # An updated agent can bootstrap the static owner page itself, so existing installations
        # gain the portal after a normal agent update rather than a full reinstall.
        try:
            # Refresh on every agent start. The page carries no secrets; keeping it current lets
            # a normal agent update deliver owner-facing improvements without a reinstall.
            req = urllib.request.Request(self.agent.server + "/api/agent/files/device.html")
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
            if b"<html" not in content.lower():
                raise ValueError("invalid owner page")
            with open(self.page_path + ".new", "wb") as f:
                f.write(content)
            os.replace(self.page_path + ".new", self.page_path)
            with open(self.page_path, "rb") as f:
                return f.read()
        except Exception as e:
            log.warning("owner portal page unavailable: %s", e)
            return b"<h1>Aegis owner portal is starting</h1><p>Refresh this page in a moment.</p>"

    def start(self) -> None:
        agent = self.agent
        page = self._page()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt, *_args):
                pass  # local page refreshes should not flood the agent log

            def send_body(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def state(self) -> None:
                try:
                    payload = agent._request("GET", f"/api/agents/{agent.agent_id}/owner/state", timeout=12)
                    self.send_body(200, json.dumps(payload).encode(), "application/json; charset=utf-8")
                except Exception as e:
                    self.send_body(502, json.dumps({"detail": f"Aegis console unavailable: {e}"}).encode(), "application/json; charset=utf-8")

            def do_GET(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                if path in ("/", "/index.html"):
                    self.send_body(200, page, "text/html; charset=utf-8")
                elif path == "/api/device/state":
                    self.state()
                else:
                    self.send_body(404, b'{"detail":"not found"}', "application/json; charset=utf-8")

            def do_POST(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                if path != "/api/device/uninstall":
                    self.send_body(404, b'{"detail":"not found"}', "application/json; charset=utf-8")
                    return
                try:
                    payload = agent._request("POST", f"/api/agents/{agent.agent_id}/owner/uninstall", timeout=12)
                    self.send_body(200, json.dumps(payload).encode(), "application/json; charset=utf-8")
                except urllib.error.HTTPError as e:
                    detail = e.read() or b'{"detail":"request failed"}'
                    self.send_body(e.code, detail, "application/json; charset=utf-8")
                except Exception as e:
                    self.send_body(502, json.dumps({"detail": f"Aegis console unavailable: {e}"}).encode(), "application/json; charset=utf-8")

        try:
            self.httpd = ThreadingHTTPServer(("127.0.0.1", OWNER_PORT), Handler)
            threading.Thread(target=self.httpd.serve_forever, daemon=True, name="owner_portal").start()
            log.info("owner portal listening on http://127.0.0.1:%s", OWNER_PORT)
        except OSError as e:
            log.warning("owner portal not started: %s", e)

    def close(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


# --------------------------------------------------------------------------- agent
class Agent:
    def __init__(self, server: str, token: str, agent_id: str, install_id: Optional[str] = None,
                 service: bool = False):
        self.server = server.rstrip("/")
        self.token = token
        self.agent_id = agent_id
        self.install_id = install_id
        self.service = service
        self.hostname = socket.gethostname()
        self.buffer: collections.deque = collections.deque(maxlen=50_000)
        self.lock = threading.Lock()
        self.subscriptions: list = []  # keep handles alive
        self._callback_ref = EVT_CALLBACK(self._callback)  # keep the C callback alive
        self.channels_ok: List[str] = []
        self.channels_failed: Dict[str, str] = {}
        self.own_pids = {str(os.getpid())}
        sup = os.environ.get("AEGIS_SUPERVISOR_PID")
        if sup:
            self.own_pids.add(sup)
        if getattr(sys, "frozen", False):  # PyInstaller bootloader is our parent
            self.own_pids.add(str(os.getppid()))
        self.own_image = os.path.normcase(sys.executable)
        self.stop = threading.Event()
        self.sent = 0
        self.started = time.time()
        self.user = current_user()
        self.exit_code = 0
        self.last_contact = time.time()
        self.canaries: Dict[str, Dict[str, Any]] = {}  # path -> {sig, root, drill, magic}
        self.canary_lock = threading.Lock()
        self.last_trip: Optional[Dict[str, Any]] = None
        self.owner_portal = OwnerPortal(self) if self.service else None

    # ---- http
    def _request(self, method: str, path: str, body: Any = None, timeout: float = 8) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.server + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Agent-Token", self.token)
        req.add_header("X-Agent-Id", self.agent_id)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None

    # ---- filtering
    def keep(self, ev: Dict[str, Any]) -> bool:
        d = ev["data"]
        # never ship our own activity (avoids a feedback loop of agent network/DNS events)
        for k in ("ProcessId", "SourceProcessId", "NewProcessId"):
            if d.get(k) in self.own_pids:
                return False
        if os.path.normcase(d.get("Image", "")) == self.own_image and ev["event_id"] in (3, 22):
            return False
        eid = ev["event_id"]
        if ev["channel"] == "Security":
            if eid == 4624 and d.get("LogonType") in ("0", "4", "5"):  # system/batch/service noise
                return False
            if eid == 4624 and d.get("TargetUserSid") == SYSTEM_SID:
                return False
            if eid == 4672 and d.get("SubjectUserSid") == SYSTEM_SID:
                return False
        return True

    # ---- event log subscriptions (called on a Windows thread-pool thread)
    def _callback(self, action, context, evt):
        if action != EVT_ACTION_DELIVER:
            if action == EVT_ACTION_ERROR:
                log.warning("subscription error %s", evt)
            return 0
        try:
            ev = parse_event_xml(render_xml(evt))
            if ev and self.keep(ev):
                with self.lock:
                    self.buffer.append(ev)
        except Exception:
            log.exception("failed to process event")
        return 0

    def subscribe(self) -> None:
        for channel, ids in CHANNELS.items():
            h = wevtapi.EvtSubscribe(None, None, channel, xpath_for(ids), None, None,
                                     self._callback_ref, EVT_SUBSCRIBE_TO_FUTURE)
            if h:
                self.subscriptions.append(h)
                self.channels_ok.append(channel)
                log.info("subscribed: %s", channel)
            else:
                err = ctypes.get_last_error()
                reason = {5: "access denied", 15007: "channel not found (not installed)"}.get(err, f"error {err}")
                self.channels_failed[channel] = reason
                log.warning("cannot subscribe to %s (%s) - skipping", channel, reason)

    # ---- loops
    def sender_loop(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            with self.lock:
                batch = [self.buffer.popleft() for _ in range(min(500, len(self.buffer)))]
            if not batch:
                time.sleep(0.3)
                continue
            try:
                self._request("POST", "/api/ingest", {
                    "agent_id": self.agent_id, "hostname": self.hostname, "events": batch,
                    "sent_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z",
                })
                self.sent += len(batch)
                backoff = 1.0
            except urllib.error.HTTPError as e:
                if e.code == 401:  # this endpoint was removed from the console
                    log.error("backend rejected our key (401); dropping batch")
                    self.stop.wait(15)
                    continue
                self._requeue(batch, e, backoff)
                backoff = min(backoff * 2, 15)
            except (urllib.error.URLError, OSError) as e:
                self._requeue(batch, e, backoff)
                backoff = min(backoff * 2, 15)

    def _requeue(self, batch, err, backoff) -> None:
        log.warning("ingest failed (%s); retrying in %.0fs", err, backoff)
        with self.lock:
            self.buffer.extendleft(reversed(batch))
        self.stop.wait(backoff)

    def heartbeat_loop(self) -> None:
        n = 0
        while not self.stop.is_set():
            if n % 12 == 0:
                self.user = current_user()
            n += 1
            try:
                self._request("POST", "/api/agents/heartbeat", {
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "ip": local_ip_towards(self.server),
                    "os": os_name(),
                    "os_version": platform.version(),
                    "arch": platform.machine(),
                    "user": self.user,
                    "is_admin": is_admin(),
                    "agent_version": AGENT_VERSION,
                    "channels": self.channels_ok,
                    "channels_failed": self.channels_failed,
                    "events_sent": self.sent,
                    "buffered": len(self.buffer),
                    "install_id": self.install_id,
                    "mode": "service" if self.service else "manual",
                    "uptime": int(time.time() - self.started),
                    "isolation": self.isolation_status(),
                    "canary": self.canary_status(),
                })
                self.last_contact = time.time()
            except Exception as e:  # never let this thread die
                log.warning("heartbeat failed: %s", e)
                self.isolation_failsafe()
            self.stop.wait(5)

    def command_loop(self) -> None:
        while not self.stop.is_set():
            try:
                cmds = self._request("GET", f"/api/agents/{self.agent_id}/commands/pending") or []
                for cmd in cmds:
                    status, result = self.execute(cmd)
                    self._request("POST", f"/api/commands/{cmd['id']}/result", {"status": status, "result": result})
                    if cmd.get("type") in ("update", "uninstall") and status == "done":
                        self.exit_code = EXIT_RESTART if cmd["type"] == "update" else 0
                        self.stop.set()
            except Exception as e:  # never let this thread die (e.g. backend restarting mid-request)
                log.warning("command poll failed: %s", e)
                self.stop.wait(2)
            self.stop.wait(1)

    # ---- response actions
    def execute(self, cmd: Dict[str, Any]):
        ctype, args = cmd.get("type"), cmd.get("args") or {}
        log.info("command %s %s", ctype, args)
        try:
            if ctype == "ping":
                return "done", {"pong": time.time(), "hostname": self.hostname}
            if ctype == "kill_process":
                pid = int(args["pid"])
                out = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                ok = out.returncode == 0
                return ("done" if ok else "failed"), {"pid": pid, "output": (out.stdout or out.stderr).strip()}
            if ctype == "run_test":
                return self.run_test(str(args.get("test")))
            if ctype == "isolate_host":
                return self.isolate(args)
            if ctype == "release_host":
                return self.release(args)
            if ctype == "update":
                return self.update()
            if ctype == "uninstall":
                return self.uninstall()
            return "failed", {"error": f"unknown command {ctype}"}
        except Exception as e:
            return "failed", {"error": str(e)}

    def update(self):
        """Pull the latest agent.py from the backend; the supervisor restarts us on it."""
        if not self.service:
            return "failed", {"error": "self-update needs the installed service; re-download agent.py by hand"}
        req = urllib.request.Request(self.server + "/api/agent/files/agent.py")
        with urllib.request.urlopen(req, timeout=20) as resp:
            src = resp.read()
        compile(src, "agent.py", "exec")  # refuse to install something that does not even parse
        path = os.path.join(HERE, "agent.py")
        with open(path + ".new", "wb") as f:
            f.write(src)
        os.replace(path + ".new", path)
        return "done", {"bytes": len(src), "from_version": AGENT_VERSION}

    def uninstall(self):
        """Run uninstall.ps1 outside the scheduled task's job so stopping the task cannot kill it."""
        script = os.path.join(HERE, "uninstall.ps1")
        if not self.service or not os.path.exists(script):
            return "failed", {"error": "not an installed agent (no uninstall.ps1)"}
        cmdline = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}" -Quiet'
        ps = ("Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
              f"-Arguments @{{CommandLine='{cmdline}'}} | Out-Null")
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps], timeout=30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return "done", {"uninstalling": True}

    # ---- "Test my protection": harmless, fixed simulations only. The backend picks a
    # test by name; it can never send a command line of its own.
    SAFE_TESTS = ("encoded_powershell", "recon_burst", "ransomware_sim")

    def run_test(self, test: str):
        if test not in self.SAFE_TESTS:
            return "failed", {"error": f"unknown test {test}"}
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if test == "ransomware_sim":
            files = self.drill_seed()
            p = subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", DRILL_SCRIPT],
                                 creationflags=flags)
            return "done", {"test": test, "pid": p.pid, "started": time.time(), "files": files, "folder": DRILL_DIR}
        if test == "encoded_powershell":
            # -enc of "Start-Sleep -Seconds 300": looks like an obfuscated payload, does nothing
            import base64
            payload = base64.b64encode("Start-Sleep -Seconds 300".encode("utf-16-le")).decode()
            p = subprocess.Popen(["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-enc", payload],
                                 creationflags=flags)
            return "done", {"test": test, "pid": p.pid, "started": time.time()}
        # recon_burst: the discovery commands an intruder runs first, read-only
        pids = []
        for cmd in (["whoami", "/all"], ["hostname"], ["ipconfig", "/all"], ["net", "user"]):
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
            pids.append(p.pid)
            p.wait(timeout=30)
        return "done", {"test": test, "pids": pids, "started": time.time()}

    # ---- ransomware canaries
    def canary_roots(self) -> List[str]:
        roots = [os.path.join(os.environ.get("PUBLIC") or r"C:\Users\Public", "Documents")]
        user = (self.user or "").split("\\")[-1]
        if user and user != "unknown":
            drive = os.environ.get("SystemDrive", "C:")
            roots.append(os.path.join(drive + "\\", "Users", user, "Documents"))
        if not self.service:  # manual run as a normal user
            roots.append(os.path.join(os.path.expanduser("~"), "Documents"))
        seen, out = set(), []
        for r in roots:
            k = os.path.normcase(r)
            if k not in seen and os.path.isdir(r):
                seen.add(k)
                out.append(r)
        return out

    def _arm(self, path: str, magic: bytes, root: str, drill: bool, rewrite: bool = False) -> None:
        if rewrite or not os.path.exists(path):
            write_decoy(path, magic)
        sig = file_sig(path)
        if sig:
            self.canaries[path] = {"sig": sig, "root": root, "drill": drill, "magic": magic}

    def canary_arm(self, rewrite: Optional[set] = None) -> None:
        """Plant (or re-plant) the decoys; `rewrite` = paths whose content must be restored."""
        rewrite = rewrite or set()
        with self.canary_lock:
            for root in self.canary_roots():
                d = os.path.join(root, CANARY_DIRNAME)
                try:
                    os.makedirs(d, exist_ok=True)
                    kernel32.SetFileAttributesW(d, 0x2)  # hidden: invisible to people, not to ransomware
                    for name, magic in CANARY_FILES:
                        p = os.path.join(d, name)
                        self._arm(p, magic, root, False, p in rewrite)
                except OSError as e:
                    log.warning("cannot plant canaries in %s: %s", d, e)
            for p in rewrite:  # drill decoys are not re-planted; the next drill reseeds the folder
                if self.canaries.get(p, {}).get("drill"):
                    self.canaries.pop(p, None)

    def canary_status(self) -> Dict[str, Any]:
        with self.canary_lock:
            real = [p for p, c in self.canaries.items() if not c["drill"]]
            drill = len(self.canaries) - len(real)
        return {"armed": len(real), "drill": drill, "folders": sorted({os.path.dirname(p) for p in real}),
                "last_trip": self.last_trip}

    def drill_seed(self) -> int:
        """A fresh folder of throwaway documents with two canaries hidden among them."""
        import shutil
        with self.canary_lock:
            for p in [p for p, c in self.canaries.items() if c["drill"]]:
                self.canaries.pop(p)
        shutil.rmtree(DRILL_DIR, ignore_errors=True)
        os.makedirs(DRILL_DIR, exist_ok=True)
        n = 0
        for prefix, ext, magic in DRILL_GROUPS:
            for i in range(1, 21):
                write_decoy(os.path.join(DRILL_DIR, f"{prefix}-{i:03d}{ext}"), magic, 64 * 1024)
                n += 1
        with self.canary_lock:
            for name, magic in DRILL_CANARIES:
                self._arm(os.path.join(DRILL_DIR, name), magic, DRILL_DIR, True, rewrite=True)
        return n + len(DRILL_CANARIES)

    def canary_check(self) -> Optional[tuple]:
        with self.canary_lock:
            items = list(self.canaries.items())
        for path, c in items:
            sig = file_sig(path)
            if sig == c["sig"]:
                continue
            if sig is None:
                d, base = os.path.split(path)
                try:
                    moved = next((f for f in os.listdir(d) if f.startswith(os.path.basename(path) + ".")), None)
                except OSError:
                    moved = None
                return path, c, (f"renamed to {moved}" if moved else "deleted")
            return path, c, "modified"
        return None

    def canary_loop(self) -> None:
        try:
            self.canary_arm()
        except Exception:
            log.exception("canary setup failed")
        log.info("ransomware canaries armed: %d", len(self.canaries))
        prev = cur = io_snapshot()
        n, quiet_until = 0, 0.0
        while not self.stop.wait(0.2):
            n += 1
            try:
                if n % 5 == 0:  # write-volume baseline, kept 1-2 s old
                    prev, cur = cur, io_snapshot()
                if n % 300 == 0:  # once a minute: new user signed in, decoy cleaned up, etc.
                    self.canary_arm()
                if time.time() < quiet_until:
                    continue
                hit = self.canary_check()
                if hit:
                    self.canary_respond(*hit, baseline=prev)
                    quiet_until = time.time() + CANARY_COOLDOWN_S
            except Exception:
                log.exception("canary loop error")

    def _rank_writers(self, before: Dict[int, tuple], after: Dict[int, tuple], limit: int = 3) -> List[Dict[str, Any]]:
        out = []
        for pid, (r, w) in after.items():
            if pid in (0, 4) or str(pid) in self.own_pids:
                continue
            br, bw = before.get(pid, (0, 0))
            if w - bw > 0:
                out.append({"pid": pid, "write": w - bw, "read": r - br})
        out.sort(key=lambda x: -x["write"])
        ranked = []
        for c in out:
            info = proc_info(c["pid"])
            img = info["image"]
            if os.path.normcase(img) == self.own_image or os.path.basename(img).lower() in PROTECTED_IMAGES or not img:
                continue
            ranked.append({**c, "image": img, "started": info["started"]})
            if len(ranked) == limit:
                break
        return ranked

    @staticmethod
    def _match_churn(ranked: List[Dict[str, Any]], exp_read: int, exp_write: int) -> List[Dict[str, Any]]:
        """Byte accounting: the encryptor's own I/O counters must match what changed in the folder.
        It reads the originals and writes the locked copies, so its read and write deltas track the
        folder's churn; a browser flushing its cache writes a lot but nothing that matches."""
        if exp_write < CHURN_MIN_BYTES:
            return []
        return [c for c in ranked
                if 0.5 * exp_write <= c["write"] <= 2.5 * exp_write + 256 * 1024
                and c["read"] > 0 and c["read"] >= 0.3 * exp_read]

    def canary_respond(self, path: str, c: Dict[str, Any], change: str, baseline: Dict[int, tuple]) -> None:
        tripped = time.time()
        dirs = list(dict.fromkeys([os.path.dirname(path), c["root"]]))
        ranked: List[Dict[str, Any]] = []
        clear, exp_read, exp_write, matches = False, 0, 0, []
        for _ in range(CHURN_WINDOWS):
            # watch the folder while it is being encrypted and see whose I/O accounts for it
            s0, io0 = dir_state(dirs), io_snapshot()
            if self.stop.wait(CHURN_WINDOW_S):
                return
            s1, io1 = dir_state(dirs), io_snapshot()
            exp_read, exp_write = churn(s0, s1)
            ranked = self._rank_writers(io0, io1, limit=8)
            matches = self._match_churn(ranked, exp_read, exp_write)
            if len(matches) == 1:
                clear = True
                break
            if exp_write < CHURN_MIN_BYTES:
                break  # nothing is encrypting any more: the attack is over, do not kill a bystander
        if clear:
            ranked = matches + [r for r in ranked if r is not matches[0]]
        top = ranked[0] if ranked else None
        action, killed_at = "no suspect found", None
        if top and clear:
            if terminate(top["pid"]):
                killed_at = time.time()
                action = "killed"
            else:
                action = "kill failed"
        elif exp_write < CHURN_MIN_BYTES:
            action = "not killed: encryption had already stopped"
        elif top:
            action = "suspect not killed (ambiguous)"
        log.warning("CANARY %s %s -> %s pid=%s: %s", path, change, top and top["image"], top and top["pid"], action)

        since = (top or {}).get("started") or (tripped - 60)
        dmg = count_damage(c["root"], since, DRILL_EXT if c["drill"] else None)
        data = {
            "CanaryFile": path, "Change": change, "Action": action, "Confidence": "high" if clear else "low",
            "TrippedAt": iso_utc(tripped), "ScanRoot": c["root"], "Drill": "true" if c["drill"] else "false",
            "FilesAffected": str(dmg["changed"]), "FilesScanned": str(dmg["total"]),
            "ScanTruncated": "true" if dmg["truncated"] else "false",
            "FolderBytesRead": str(exp_read), "FolderBytesWritten": str(exp_write),
            "Suspects": json.dumps([{"image": os.path.basename(s["image"]), "pid": s["pid"], "write": s["write"]}
                                    for s in ranked]),
        }
        if top:
            data.update({"Image": top["image"], "ProcessId": str(top["pid"]), "BytesWritten": str(top["write"])})
            if top.get("started"):
                data["ProcessStartedAt"] = iso_utc(top["started"])
        if killed_at:
            data["KilledAt"] = iso_utc(killed_at)
            data["KillMs"] = str(int((killed_at - tripped) * 1000))
        self.last_trip = {"at": tripped, "file": path, "action": action, "image": data.get("Image")}
        with self.lock:
            self.buffer.appendleft({"ts": iso_utc(tripped), "channel": CANARY_CHANNEL, "provider": "Aegis",
                                    "event_id": 1, "record_id": None, "data": data})
        try:
            # every decoy this attack already hit is handled now; without this the next one
            # trips again after the cooldown and blames whoever happens to be writing then
            with self.canary_lock:
                hit = {p for p, x in self.canaries.items() if x["root"] == c["root"] and file_sig(p) != x["sig"]}
            self.canary_arm(rewrite=hit | {path})
        except Exception:
            log.exception("canary re-arm failed")

    # ---- network isolation
    # Windows Firewall BLOCK rules in our own group. Block rules beat every allow rule already on
    # the machine, so app exceptions cannot leak. The only addresses left out of the block ranges
    # are the console's, and DHCP stays open so the laptop keeps its IP lease (losing it would
    # strand the host where not even the console can release it).
    def isolation_status(self) -> Dict[str, Any]:
        st = isolation_load()
        if not st:
            return {"isolated": False}
        return {"isolated": True, "since": st.get("since"), "console_ips": st.get("console_ips"),
                "alert_id": st.get("alert_id")}

    def isolate(self, args: Dict[str, Any]):
        if isolation_load():
            return "done", {"already": True, **self.isolation_status()}
        host = urllib.parse.urlparse(self.server).hostname or ""
        ips = sorted({ai[4][0] for ai in _real_getaddrinfo(host, None) if ai[0] in (socket.AF_INET, socket.AF_INET6)})
        if not ips:
            return "failed", {"error": f"could not resolve the console {host}"}
        if any(ipaddress.ip_address(i).is_loopback for i in ips):
            return "failed", {"error": "console is on loopback; nothing to isolate from"}
        prior = run_ps("Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{Name=$_.Name; "
                       "Enabled=\"$($_.Enabled)\"} } | ConvertTo-Json -Compress")
        prior_profiles = json.loads(prior or "[]")
        if isinstance(prior_profiles, dict):
            prior_profiles = [prior_profiles]
        state = {"since": time.time(), "console_host": host, "console_ips": ips, "prior_profiles": prior_profiles,
                 "alert_id": args.get("alert_id")}
        isolation_save(state)  # written first so a half-applied isolation can always be released
        PINNED_HOSTS[host] = ips
        try:
            run_ps(isolation_rules_script(ips))
        except Exception as e:
            err = f"firewall rules failed: {e}"
            try:
                self.release({})
            except Exception as e2:  # keep isolation.json so the failsafe / break-glass can still lift it
                err += f"; rollback also failed: {e2}"
            log.error("isolate: %s", err)
            return "failed", {"error": err}
        probe = tcp_probe("1.1.1.1", 443)
        return "done", {"isolated": True, "console_ips": ips,
                        "probe": "internet blocked" if not probe else "WARNING: 1.1.1.1:443 still reachable"}

    def release(self, args: Dict[str, Any]):
        st = isolation_load()
        # 1. the block rules: if this fails we stay "isolated" (state file and pinned console IPs kept),
        #    so the agent can still reach the console and the failsafe can retry
        # `exit 0`: with no rules in the group the silenced lookup still leaves $? false, and powershell
        # would exit 1 - which used to make every release after a failed isolate fail too
        run_ps(f"Get-NetFirewallRule -Group '{ISOLATION_GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; exit 0")
        left = run_ps(f"@(Get-NetFirewallRule -Group '{ISOLATION_GROUP}' -ErrorAction SilentlyContinue).Count")
        if left.strip() not in ("", "0"):
            raise RuntimeError(f"{left.strip()} isolation firewall rules are still in place")
        # 2. firewall on/off as it was before; best effort, it never blocks the release
        warnings = []
        for p in (st or {}).get("prior_profiles") or []:
            if p.get("Enabled") in ("True", "False") and p.get("Name"):
                try:
                    run_ps(f"Set-NetFirewallProfile -Name '{p['Name']}' -Enabled {p['Enabled']}")
                except Exception as e:
                    warnings.append(f"{p['Name']}: {e}")
        try:
            os.remove(ISOLATION_STATE)
        except FileNotFoundError:
            pass
        # keep the console pinned: DNS may take a moment to work again, and the pinned IPs are still right.
        # They are dropped on the next agent restart.
        out = {"isolated": False, "was_isolated": bool(st)}
        if warnings:
            out["warnings"] = warnings
        return "done", out

    def isolation_failsafe(self) -> None:
        if ISOLATION_FAILSAFE_MIN and isolation_load() and time.time() - self.last_contact > ISOLATION_FAILSAFE_MIN * 60:
            log.warning("console unreachable for %d min while isolated - lifting isolation (failsafe)",
                        ISOLATION_FAILSAFE_MIN)
            try:
                self.release({})
            except Exception as e:
                log.error("failsafe release failed: %s", e)

    def run(self) -> int:
        st = isolation_load()
        if st:  # firewall rules survive a reboot; keep reaching the console by its pinned address
            PINNED_HOSTS[st["console_host"]] = st["console_ips"]
            log.warning("host is ISOLATED since %s; console pinned to %s", time.ctime(st["since"]), st["console_ips"])
        if not is_admin():
            log.warning("NOT running as Administrator - Security log will be unavailable")
        self.subscribe()
        if not self.channels_ok:
            log.error("no event channels available - is Sysmon installed?")
            return 1
        if self.owner_portal:
            self.owner_portal.start()
        for fn in (self.sender_loop, self.heartbeat_loop, self.command_loop, self.canary_loop):
            threading.Thread(target=fn, daemon=True, name=fn.__name__).start()
        log.info("agent %s v%s (%s) shipping to %s", self.agent_id, AGENT_VERSION, self.hostname, self.server)
        try:
            while not self.stop.wait(10):
                log.info("sent=%d buffered=%d", self.sent, len(self.buffer))
        except KeyboardInterrupt:
            self.stop.set()
        # give the sender a moment to flush what is queued
        deadline = time.time() + 3
        while self.buffer and time.time() < deadline and self.exit_code == EXIT_RESTART:
            time.sleep(0.2)
        for h in self.subscriptions:
            wevtapi.EvtClose(h)
        if self.owner_portal:
            self.owner_portal.close()
        log.info("stopping (exit %d)", self.exit_code)
        return self.exit_code


# --------------------------------------------------------------------------- supervisor
def supervise(argv: List[str]) -> None:
    """--service mode: keep a worker process running and restart it on crash or after an update.

    The scheduled task starts this; the worker is the same file with --worker, so an update
    swaps agent.py on disk and the next worker runs the new code.
    """
    env = dict(os.environ, AEGIS_SUPERVISOR_PID=str(os.getpid()))
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    quick_fails = 0
    while True:
        started = time.time()
        p = subprocess.Popen([sys.executable, os.path.join(HERE, "agent.py"), "--worker", *argv],
                             env=env, creationflags=flags)
        code = p.wait()
        log.info("worker exited with %s", code)
        if code == 0:
            return  # uninstall or clean stop
        if code == EXIT_RESTART:
            quick_fails = 0
            continue
        quick_fails = quick_fails + 1 if time.time() - started < 30 else 0
        time.sleep(min(60, 2 ** min(quick_fails, 6)))


def setup_logging(verbose: bool, log_file: Optional[str]) -> None:
    handlers: List[logging.Handler] = []
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=2,
                                                             encoding="utf-8"))
    if sys.stderr is not None:  # pythonw has no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(process)d %(levelname)s %(message)s")


def main() -> None:
    cfg = load_config()
    p = argparse.ArgumentParser(description="Aegis Windows agent")
    p.add_argument("--server", default=os.environ.get("AEGIS_SERVER") or cfg.get("server") or "http://172.16.49.1:8000")
    p.add_argument("--token", default=os.environ.get("AEGIS_TOKEN") or cfg.get("key") or "hackathon-demo-token")
    p.add_argument("--id-file", default=os.path.join(HERE, "agent_id.txt"))
    p.add_argument("--service", action="store_true", help="supervisor mode (used by the scheduled task)")
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--release-isolation", action="store_true",
                   help="lift network isolation locally (break-glass, needs Administrator)")
    a = p.parse_args()

    if a.release_isolation:
        status, res = Agent(a.server, a.token, "local").release({})
        print(status, res)
        return

    installed = bool(cfg.get("agent_id"))
    log_file = os.path.join(HERE, "logs", "agent.log") if (a.service or a.worker or installed) else None
    setup_logging(a.verbose, log_file)

    if a.service:
        log.info("supervisor starting (agent v%s)", AGENT_VERSION)
        supervise(["-v"] if a.verbose else [])
        return

    agent_id = cfg.get("agent_id") or _load_id(a.id_file)
    agent = Agent(a.server, a.token, agent_id, cfg.get("install_id"), service=a.worker)
    sys.exit(agent.run())


def _load_id(path: str) -> str:
    try:
        with open(path) as f:
            v = f.read().strip()
            if v:
                return v
    except FileNotFoundError:
        pass
    v = str(uuid.uuid4())
    with open(path, "w") as f:
        f.write(v)
    return v


if __name__ == "__main__":
    main()
