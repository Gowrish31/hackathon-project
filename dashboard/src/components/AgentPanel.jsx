import { useEffect, useState } from "react";
import { api, isOnline, ago, fmtTime, catStyle, sevStyle, statusStyle } from "../lib/live.js";
import Onboarding from "./Onboarding.jsx";
import { IsolateControl, IsolationBanner } from "./Isolation.jsx";

const CHANNEL_NAMES = {
  "Microsoft-Windows-Sysmon/Operational": "Sysmon",
  "Security": "Security",
  "Microsoft-Windows-PowerShell/Operational": "PowerShell",
  "Microsoft-Windows-Windows Defender/Operational": "Defender",
  "System": "System",
};

/** Fleet view: onboarding on top, then every enrolled endpoint, its health and the last action sent to it. */
export default function Endpoints({ agents, commands, cmdLog, alerts, events, installs, requests, scope, onScope, onOpenAlert, adding, onAdding }) {
  const [, force] = useState(0);
  useEffect(() => {
    const id = setInterval(() => force((n) => n + 1), 5000);
    return () => clearInterval(id);
  }, []);
  const list = Object.values(agents).sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""));
  const showAdd = adding || !list.length;

  const openHost = (id) => {
    onAdding(false);
    requestAnimationFrame(() => document.getElementById(`host-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

  return (
    <div className="flex-1 overflow-y-auto">
      {showAdd && <Onboarding installs={installs} requests={requests} onOpenHost={openHost} onClose={list.length ? () => onAdding(false) : null} />}
      <div className="grid gap-4 p-5">
        {!showAdd && (
          <div className="flex items-center">
            <p className="text-xs text-muted">{list.length} endpoint{list.length === 1 ? "" : "s"} enrolled</p>
            <button onClick={() => onAdding(true)}
              className="ml-auto flex h-8 items-center gap-2 rounded-md bg-accent px-3.5 text-[13px] font-medium text-bg transition hover:brightness-110">
              <svg width="11" height="11" viewBox="0 0 12 12" aria-hidden="true"><path d="M6 1.5v9M1.5 6h9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
              Add endpoint
            </button>
          </div>
        )}
        {list.map((a) => <HostCard key={a.id} a={a} cmd={commands[a.id]} cmdLog={cmdLog} alerts={alerts} events={events}
          scope={scope} onScope={onScope} onOpenAlert={onOpenAlert} />)}
      </div>
    </div>
  );
}

const ACTION_NAMES = { kill_process: (c) => `terminate PID ${c.args?.pid}`, run_test: () => "detection drill", update: () => "agent update", uninstall: () => "uninstall", isolate_host: () => "network isolation", release_host: () => "release from isolation" };

function HostCard({ a, cmd, cmdLog, alerts, events, scope, onScope, onOpenAlert }) {
  const [confirm, setConfirm] = useState(false);
  const online = isOnline(a);
  const never = !a.last_seen;
  const open = alerts.filter((x) => x.agent_id === a.id && (x.status === "open" || x.status === "acknowledged")).length;
  const channels = a.info?.channels || [];
  const failed = Object.entries(a.info?.channels_failed || {});
  const installed = a.info?.mode === "service";
  const removing = cmd?.type === "uninstall" && cmd.status !== "failed";
  const remove = async () => {
    setConfirm(false);
    if (online && installed) await api.del(`/api/agents/${a.id}?uninstall=true`);
    else await api.del(`/api/agents/${a.id}`);
  };
  const btn = "h-7 rounded-md border border-line px-2.5 text-xs text-text-2 hover:border-text-2/40 hover:text-text disabled:opacity-40";

  return (
    <article id={`host-${a.id}`} className={`grid scroll-mt-4 overflow-hidden rounded-xl border bg-surface lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)] ${scope === a.id ? "border-accent/50" : "border-line"} ${removing ? "opacity-60" : ""}`}>
      <div className="min-w-0 lg:border-r lg:border-line-soft">
      <div className="flex items-start gap-3 border-b border-line-soft px-5 py-4">
        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${online ? "live-ring bg-ok text-ok" : "bg-muted"}`} />
        <div className="min-w-0">
          <h2 className="text-[17px] font-semibold leading-tight">{a.hostname || a.id.slice(0, 8)}</h2>
          <p className="mt-0.5 text-xs text-muted">
            {removing ? "Uninstalling…" : online ? "Reporting" : never ? "Enrolled, waiting for first check-in" : `Offline, last seen ${ago(a.last_seen)}`}
            {open > 0 && <span className="text-crit">, {open} open alert{open === 1 ? "" : "s"}</span>}
          </p>
        </div>
        <div className="ml-auto flex flex-wrap justify-end gap-2">
          {confirm ? (
            <>
              <span className="self-center text-xs text-text-2">
                {online && installed ? "Uninstall the agent and Sysmon from this machine?" : "Remove this endpoint from the console?"}
              </span>
              <button onClick={remove} className="h-7 rounded-md bg-crit px-2.5 text-xs font-medium text-white hover:brightness-110">
                {online && installed ? "Uninstall" : "Remove"}
              </button>
              <button onClick={() => setConfirm(false)} className={btn}>Cancel</button>
            </>
          ) : (
            <>
              <button onClick={() => api.post(`/api/agents/${a.id}/commands`, { type: "ping" })} disabled={!online} className={btn}>Ping</button>
              {installed && (
                <button onClick={() => api.post(`/api/agents/${a.id}/commands`, { type: "update" })} disabled={!online}
                  title="Push the console's current agent.py to this machine" className={btn}>Update agent</button>
              )}
              <IsolateControl agent={a} cmdLog={cmdLog} small />
              <button onClick={() => onScope(scope === a.id ? null : a.id)}
                className={`h-7 rounded-md border px-2.5 text-xs ${scope === a.id ? "border-accent/50 bg-accent/10 text-accent" : "border-line text-text-2 hover:border-text-2/40 hover:text-text"}`}>
                {scope === a.id ? "Showing this host" : "Focus on host"}
              </button>
              <button onClick={() => setConfirm(true)} disabled={removing} className={`${btn} hover:!border-crit/50 hover:!text-crit`}>Remove</button>
            </>
          )}
        </div>
      </div>
      <IsolationBanner agent={a} cmdLog={cmdLog} className="mx-5 mt-4" />
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 px-5 py-4 text-[13px]">
        <Row label="IP address" value={<span className="font-mono">{a.ip || "unknown"}</span>} />
        <Row label="Operating system" value={`${a.os || "unknown"} ${a.info?.arch || ""}`} />
        <Row label="Signed-in user" value={<span className="font-mono">{a.user || "unknown"}</span>} />
        <Row label="Agent" value={a.agent_version
          ? <>v{a.agent_version} <span className="text-muted">{installed ? "service" : "manual run"}</span></>
          : "not reported"} />
        <Row label="Privilege" value={a.is_admin
          ? (installed ? "SYSTEM" : "Administrator")
          : <span className="text-warn">Standard user, Security log unavailable</span>} />
        <Row label="Events shipped" value={(a.info?.events_sent ?? 0).toLocaleString()} />
        <Row label="Last check-in" value={<span className="font-mono">{a.last_seen ? fmtTime(a.last_seen) : "never"}</span>} />
        <Row label="Uptime" value={a.info?.uptime != null ? fmtUptime(a.info.uptime) : "unknown"} />
      </dl>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line-soft px-5 py-3 text-xs">
        <span className="text-muted">Collecting</span>
        {channels.map((c) => (
          <span key={c} className="flex items-center gap-1.5 text-text-2">
            <span className="h-1.5 w-1.5 rounded-full bg-ok" />{CHANNEL_NAMES[c] || c}
          </span>
        ))}
        {failed.map(([c, why]) => (
          <span key={c} className="flex items-center gap-1.5 text-muted" title={why}>
            <span className="h-1.5 w-1.5 rounded-full border border-muted" />{CHANNEL_NAMES[c] || c}
          </span>
        ))}
        {cmd && (
          <span className="ml-auto text-muted">
            Last action: {(ACTION_NAMES[cmd.type] || (() => cmd.type))(cmd)}{" "}
            <span className={cmd.status === "done" ? "text-ok" : cmd.status === "failed" ? "text-crit" : "text-warn"}
              title={cmd.result?.error || ""}>
              {{ done: "succeeded", failed: "failed", expired: "expired", sent: "in progress", pending: "queued" }[cmd.status] || cmd.status}
            </span>
          </span>
        )}
      </div>
      </div>
      <HostActivity events={events.filter((e) => e.agent_id === a.id)}
        alerts={alerts.filter((x) => x.agent_id === a.id)} onOpenAlert={onOpenAlert} />
    </article>
  );
}

const fmtUptime = (s) => (s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`);

function Row({ label, value }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5 truncate">{value}</dd>
    </div>
  );
}

/** Right half of a host card: what this machine has been doing and what fired on it. */
export function HostActivity({ events, alerts, onOpenAlert }) {
  const now = Date.now();
  const bins = Array(30).fill(0);
  const cats = {};
  for (const e of events) {
    const m = Math.floor((now - Date.parse(e.ts)) / 60000);
    if (m >= 0 && m < 30) bins[29 - m]++;
    cats[e.category] = (cats[e.category] || 0) + 1;
  }
  const max = Math.max(1, ...bins);
  const total = events.length || 1;
  const top = Object.entries(cats).sort((x, y) => y[1] - x[1]).slice(0, 6);
  const recent = alerts.slice().sort((x, y) => y.ts.localeCompare(x.ts)).slice(0, 4);

  return (
    <div className="min-w-0 border-t border-line-soft px-5 py-4 lg:border-t-0">
      <div className="flex items-baseline justify-between text-xs">
        <span className="font-medium text-text-2">Activity, last 30 minutes</span>
        <span className="text-muted">{bins.reduce((x, y) => x + y, 0)} events</span>
      </div>
      <div className="mt-2 flex h-10 items-end gap-[2px]" role="img" aria-label="Events per minute, last 30 minutes">
        {bins.map((v, i) => (
          <span key={i} className="flex-1 rounded-[1px] bg-accent" title={`${v} events`}
            style={{ height: v ? `${Math.max(8, (v / max) * 100)}%` : "2px", opacity: v ? 0.75 : 0.15 }} />
        ))}
      </div>

      <div className="mt-4 flex h-1.5 overflow-hidden rounded-full bg-line" aria-hidden="true">
        {top.map(([c, n]) => <span key={c} style={{ width: `${(n / total) * 100}%`, background: catStyle(c).color }} />)}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3.5 gap-y-1 text-xs">
        {top.map(([c, n]) => (
          <span key={c} className="flex items-center gap-1.5 text-text-2">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: catStyle(c).color }} />
            {catStyle(c).label} <span className="tabular-nums text-muted">{n}</span>
          </span>
        ))}
      </div>

      <div className="mt-4 text-xs font-medium text-text-2">Recent alerts</div>
      {recent.length === 0 ? (
        <p className="mt-1.5 text-xs text-muted">No detections on this host.</p>
      ) : (
        <ul className="mt-1.5">
          {recent.map((x) => (
            <li key={x.id}>
              <button onClick={() => onOpenAlert(x)}
                className="flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left text-xs -mx-2 hover:bg-raised">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: sevStyle(x.severity).color }} />
                <span className="min-w-0 flex-1 truncate">{x.rule_title}</span>
                <span className="shrink-0" style={{ color: x.status === "open" ? "var(--color-text-2)" : statusStyle(x.status).color }}>{statusStyle(x.status).label}</span>
                <span className="w-16 shrink-0 text-right text-muted">{ago(x.ts)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
