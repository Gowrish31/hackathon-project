import { useEffect, useState } from "react";
import { api, ago, basename, caseNo, eventCategory, fmtTime, isOnline } from "../lib/live.js";
import { SeverityMark, StatusMark, useAlertCommands } from "./Alerts.jsx";
import ProcessGraph from "./ProcessGraph.jsx";
import AttackStory from "./AttackStory.jsx";
import Inspector from "./Inspector.jsx";
import Analyst from "./Analyst.jsx";
import Verify from "./Verify.jsx";
import KillSwitch from "./KillSwitch.jsx";
import ProtectionProof from "./ProtectionProof.jsx";
import { catStyle } from "../lib/live.js";
import { IsolateControl, IsolationBanner } from "./Isolation.jsx";

const CHANNELS = {
  "Microsoft-Windows-Sysmon/Operational": "Sysmon",
  "Security": "Security",
  "Microsoft-Windows-PowerShell/Operational": "PowerShell",
  "Microsoft-Windows-Windows Defender/Operational": "Defender",
  "System": "System",
};

/** One screen for the whole story: the incident that matters now, its evidence, the fleet, and proof the pipeline works. */
export default function Overview({ incidents, agents, events, cmdLog, kick, onOpenAlert, onOpenEvent, onRunTest }) {
  // the incident that matters most right now: newest unresolved, else newest of all
  const lead = incidents.filter((i) => i.status === "open" || i.status === "acknowledged")
    .sort((a, b) => b.last_ts.localeCompare(a.last_ts))[0]
    || incidents.slice().sort((a, b) => b.last_ts.localeCompare(a.last_ts))[0];
  const alert = lead?.primary || null;

  const [tree, setTree] = useState(undefined);
  const [picked, setPicked] = useState(null);
  const [busy, setBusy] = useState(false);
  const cmds = useAlertCommands(alert, cmdLog);
  useEffect(() => {
    setTree(undefined);
    setPicked(null);
    if (alert) api.get(`/api/alerts/${alert.id}/tree`).then((t) => setTree(t?.root ? t : null)).catch(() => setTree(null));
  }, [alert?.id]);

  const kills = cmds.filter((c) => c.type === "kill_process");
  const lastDone = kills.filter((c) => c.status === "done").at(-1);
  const contained = alert && (alert.status === "contained" || !!lastDone);
  const inflight = kills.some((c) => c.status === "pending" || c.status === "sent");
  const ctx = alert?.context || {};
  const pid = ctx.SourceProcessId || ctx.ProcessId;
  const procName = basename(ctx.SourceImage || ctx.Image || "") || "process";

  const kill = async () => {
    setBusy(true);
    try { await api.post(`/api/agents/${alert.agent_id}/commands`, { type: "kill_process", args: { pid: Number(pid), alert_id: alert.id } }); }
    finally { setBusy(false); }
  };

  const host = Object.values(agents).sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""))[0];
  const caseHost = alert ? agents[alert.agent_id] : null;

  return (
    <div className="flex-1 overflow-y-auto">
      <ProtectionProof agents={agents} kick={kick} onOpenAlert={onOpenAlert} />
      {/* left: investigation, then fleet + validation; right: the inspector, full height */}
      <div className={`grid min-h-full ${lead ? "min-[1180px]:grid-cols-[minmax(0,1fr)_340px]" : ""}`}>
       <div className="flex min-w-0 flex-col">
        <section className="min-w-0 px-6 pb-6 pt-5" aria-label="Incident investigation">
          {!lead ? (
            <div className="grid min-h-[260px] place-items-center text-center">
              <div>
                <p className="font-cond text-[20px] font-semibold">No open cases</p>
                <p className="mt-1 text-sm text-muted">Quiet. Run a drill to check detection end to end.</p>
                <button onClick={onRunTest} className="mt-4 h-8 rounded-md bg-accent px-3.5 text-[13px] font-medium text-bg hover:brightness-110">Run drill</button>
              </div>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 text-xs">
                <span className="font-mono font-medium text-text">{caseNo(lead.id)}</span>
                <SeverityMark sev={lead.severity} />
                <StatusMark status={contained && lead.status !== "closed" ? "contained" : lead.status} />
                <span className="text-muted">{lead.hostname}, {ago(lead.last_ts)}</span>
              </div>
              <div className="mt-1.5 flex items-start gap-4">
                <h2 className="min-w-0 flex-1 font-cond text-[24px] font-semibold leading-tight xl:text-[28px]">{lead.title}</h2>
                <div className="flex shrink-0 gap-2 pt-1">
                  {pid && !contained && (
                    <button onClick={kill} disabled={busy || inflight}
                      className="flex h-8 items-center gap-2 rounded-md bg-crit px-3 text-[13px] font-medium text-white hover:brightness-110 disabled:opacity-60">
                      {inflight ? <><span className="h-3 w-3 animate-spin rounded-full border-2 border-white/40 border-t-white" /> Killing…</> : <>Kill {procName}</>}
                    </button>
                  )}
                  {lastDone && (
                    <span className="flex h-8 items-center text-[13px] text-ok">
                      Killed in {((Date.parse(lastDone.completed_at) - Date.parse(lastDone.created_at)) / 1000).toFixed(2)} s
                    </span>
                  )}
                  <IsolateControl agent={caseHost} cmdLog={cmdLog} alertId={alert.id} />
                  <button onClick={() => onOpenAlert(alert.id)}
                    className="h-8 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text">Open case</button>
                </div>
              </div>
              <IsolationBanner agent={caseHost} cmdLog={cmdLog} className="mt-3" />
              {alert.rule_id === "IMP-002" && <div className="mt-5"><KillSwitch alert={alert} /></div>}
              <div className="mt-5">
                {tree === undefined ? <p className="text-xs text-muted">Rebuilding the process graph…</p>
                  : tree ? <ProcessGraph tree={tree} alert={alert} terminated={contained} killCmd={lastDone}
                      selectedKey={picked?.key} onSelect={(x) => setPicked(picked?.key === x.key ? null : x)} />
                  : <AttackStory alert={alert} terminated={contained} />}
              </div>
            </>
          )}
        </section>
        <div className="grid flex-1 border-t border-line min-[1380px]:grid-cols-2">
          <section className="flex min-w-0 flex-col border-line px-6 py-5 min-[1380px]:border-r" aria-label="Endpoint telemetry">
            <EndpointTelemetry host={host} events={events} cmdLog={cmdLog} />
          </section>
          <section className="flex min-w-0 flex-col border-t border-line px-6 py-5 min-[1380px]:border-t-0" aria-label="Detection drill">
            <Verify agents={agents} kick={kick} onOpenAlert={onOpenAlert} />
          </section>
        </div>
       </div>
        {lead && (
          <aside className="min-w-0 border-t border-line px-5 py-5 self-start min-[1180px]:sticky min-[1180px]:top-0 min-[1180px]:max-h-[calc(100vh-140px)] min-[1180px]:overflow-y-auto min-[1180px]:border-l min-[1180px]:border-t-0" aria-label="Evidence">
            <h2 className="mb-4 font-cond text-[19px] font-semibold">Evidence</h2>
            <div className="mb-6"><Analyst alert={alert} tree={tree} kills={kills} autoNarrate /></div>
            <Inspector alert={alert} tree={tree} kills={kills} selected={picked} onOpenEvent={onOpenEvent} compact />
          </aside>
        )}
      </div>
    </div>
  );
}

function EndpointTelemetry({ host, events, cmdLog }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 10000);
    return () => clearInterval(id);
  }, []);
  if (!host) return <p className="text-sm text-muted">No endpoint has checked in yet. Add one from Endpoints.</p>;

  const online = isOnline(host);
  const mine = events.filter((e) => e.agent_id === host.id);
  const now = Date.now();
  const bins = Array(30).fill(0);
  const cats = {};
  for (const e of mine) {
    const m = Math.floor((now - Date.parse(e.ts)) / 60000);
    if (m >= 0 && m < 30) {
      bins[29 - m]++;
      const kind = eventCategory(e);
      cats[kind] = (cats[kind] || 0) + 1;
    }
  }
  const max = Math.max(1, ...bins);
  const total = bins.reduce((a, b) => a + b, 0);
  const top = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const label = (m) => new Date(now - m * 60000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });

  return (
    <div className="flex flex-1 flex-col">
      <div className="flex items-start gap-3">
        <span className="mt-1.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-raised text-text-2">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8M12 16v4" /></svg>
        </span>
        <div className="min-w-0">
          <h2 className="font-cond text-[19px] font-semibold leading-tight">{host.hostname}</h2>
          <p className="text-xs text-muted">
            {host.os} {host.info?.arch}, <span className="font-mono">{host.ip}</span>,{" "}
            <span className={`whitespace-nowrap ${online ? "text-ok" : "text-crit"}`}>{online ? `checked in ${ago(host.last_seen)}` : `offline since ${fmtTime(host.last_seen).slice(0, 8)}`}</span>
          </p>
        </div>
        <div className="ml-auto shrink-0 whitespace-nowrap text-right">
          <div className="font-cond text-[24px] font-semibold leading-none tabular-nums">{total}</div>
          <div className="mt-1 text-xs text-muted">events / 30 min</div>
        </div>
      </div>

      <IsolationBanner agent={host} cmdLog={cmdLog} className="mt-3" />
      {host.info?.canary && (
        <p className="mt-2 text-xs text-muted" title={(host.info.canary.folders || []).join("\n")}>
          <span className={`mr-1.5 inline-block h-1.5 w-1.5 rounded-full ${host.info.canary.armed ? "bg-ok" : "bg-muted"}`} />
          Ransomware kill-switch {host.info.canary.armed ? <>armed, {host.info.canary.armed} decoy files in {(host.info.canary.folders || []).length} folders</> : "not armed"}
        </p>
      )}
      <div className="mt-4 flex min-h-24 flex-1 items-end gap-[3px]" role="img" aria-label={`Events per minute on ${host.hostname}, last 30 minutes`}>
        {bins.map((v, i) => (
          <span key={i} title={`${label(29 - i)}: ${v} events`} className="flex-1 rounded-t-[2px] bg-accent"
            style={{ height: v ? `${Math.max(6, (v / max) * 100)}%` : "2px", opacity: v ? 0.8 : 0.15 }} />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-muted">
        <span>{label(29)}</span><span>{label(15)}</span><span>now</span>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <span className="text-muted">Sources</span>
        {(host.info?.channels || []).map((c) => (
          <span key={c} className="flex items-center gap-1.5 text-text-2"><span className={`h-1.5 w-1.5 rounded-full ${online ? "bg-ok" : "bg-muted"}`} />{CHANNELS[c] || c}</span>
        ))}
      </div>
      {top.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
          <span className="text-muted">Top</span>
          {top.map(([c, n]) => (
            <span key={c} className="flex items-center gap-1.5 text-text-2">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: catStyle(c).color }} />{catStyle(c).label} <span className="tabular-nums text-muted">{n}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
