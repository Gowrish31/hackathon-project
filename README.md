# Aegis: Windows SIEM + EDR

Agent on a Windows VM → FastAPI backend on the Mac → live React dashboard.

```
Windows VM (VMware Fusion, NAT)              Mac (172.16.49.1)
┌─────────────────────────────┐   HTTP    ┌───────────────────────────┐
│ Sysmon + Security/PS logs   │ ────────▶ │ backend  :8000            │
│ agent/agent.py              │ ◀──────── │  ingest · SQLite · WS     │
└─────────────────────────────┘  commands │ dashboard (served at /)   │
                                          └───────────────────────────┘
```

## 1. Mac: backend + dashboard
```bash
cd backend
/opt/homebrew/bin/python3.14 -m venv .venv          # first time only
.venv/bin/pip install -r requirements.txt           # first time only
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Open http://localhost:8000. The backend serves the built dashboard from `dashboard/dist`.

Working on the dashboard? Use hot reload instead:
```bash
cd dashboard && npm install && npm run dev            # http://localhost:5173 (proxies to :8000)
npm run build                                         # refresh dist/ for the backend
```
When macOS asks whether Python may accept incoming connections, click **Allow**.

## 2. Windows VM: one-time setup (PowerShell as Administrator)
1. VM network: Fusion → Settings → Network → **Share with my Mac** (NAT). In this mode the Mac is `172.16.49.1`.
   Check it from the VM: `Test-NetConnection 172.16.49.1 -Port 8000`
2. Install Python from python.org (tick "Add to PATH"), then `pip install pywin32`
3. Copy the `agent/` folder to the VM and run:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\setup\install_sysmon.ps1
   ```
4. **Take a VM snapshot** named `clean-baseline`.

## 3. Run the agent (Administrator)
```powershell
python agent.py                          # defaults to http://172.16.49.1:8000
python agent.py --server http://X.X.X.X:8000 -v
```
Check: the host card turns ONLINE, **Ping agent** returns `done`, and running `whoami` on the VM shows up in the feed.

## Event format (agent → backend)
`POST /api/ingest` with header `X-Agent-Token: hackathon-demo-token`
```json
{ "agent_id": "uuid", "hostname": "WIN-DEMO",
  "events": [{ "ts": "2026-11-02T10:00:00.1234567Z", "channel": "Microsoft-Windows-Sysmon/Operational",
               "provider": "Microsoft-Windows-Sysmon", "event_id": 1, "record_id": 123,
               "data": { "Image": "...", "CommandLine": "...", "ParentImage": "..." } }] }
```
The backend adds `category` + `summary` (`backend/normalize.py`), stores the event, and pushes it on `/ws` as
`{"type":"events"|"agent"|"command", ...}`.

## API
| Method | Path | Who |
|---|---|---|
| POST | `/api/agents/heartbeat`, `/api/ingest` | agent |
| GET | `/api/agents/{id}/commands/pending` · POST `/api/commands/{cid}/result` | agent |
| GET | `/api/agents`, `/api/events?limit&agent_id&category&q&before_id`, `/api/stats` | dashboard |
| POST | `/api/agents/{id}/commands` `{"type":"ping"\|"kill_process","args":{"pid":123}}` | dashboard |
| WS | `/ws` | dashboard |

## Plan
- **Mon**: telemetry pipeline ✅ (agent, backend, live dashboard)
- **Tue**: detection engine ✅ (23 YAML rules → alerts, alerts UI, Kill button → agent kills process tree → alert auto-marked *contained*). MITRE ATT&CK grid still TODO
- **Wed**: response (isolate host), ransomware canary kill-switch, process tree
- **Thu**: AI analyst (local Ollama `qwen2.5:7b`, free) + browser voice narration
- **Fri**: polish, rehearse, record a backup video
