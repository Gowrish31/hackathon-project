import { useState } from "react";
import { api, fmtTime, isOnline } from "../lib/live.js";

const TYPES = ["isolate_host", "release_host"];

/** Isolation state of one endpoint: the agent's heartbeat, overridden by a newer completed command. */
export function useIsolation(agent, cmdLog) {
  const mine = Object.values(cmdLog || {})
    .filter((c) => c.agent_id === agent?.id && TYPES.includes(c.type))
    .sort((a, b) => a.id - b.id);
  const last = mine.at(-1);
  const hb = agent?.info?.isolation || {};
  let isolated = !!hb.isolated;
  let since = hb.since ? new Date(hb.since * 1000) : null;
  if (last?.status === "done" && last.completed_at && (!agent?.last_seen || last.completed_at > agent.last_seen)) {
    isolated = last.type === "isolate_host";
    if (isolated && !since) since = new Date(last.completed_at);
  }
  const inflight = last && (last.status === "pending" || last.status === "sent") ? last.type : null;
  const failed = last?.status === "failed" ? last : null;
  return { isolated, since, inflight, failed, consoleIps: hb.console_ips || last?.result?.console_ips || [] };
}

const spin = <span className="h-3 w-3 animate-spin rounded-full border-2 border-current/30 border-t-current" />;

/** Isolate / Release with a one-step confirm. `small` = the h-7 endpoint-card size. */
export function IsolateControl({ agent, cmdLog, alertId, small }) {
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const iso = useIsolation(agent, cmdLog);
  if (!agent) return null;
  const online = isOnline(agent);
  const h = small ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-[13px]";
  const outline = `${h} rounded-md border border-line text-text-2 hover:border-text-2/40 hover:text-text disabled:opacity-40`;

  const send = async (type) => {
    setConfirm(false);
    setBusy(true);
    try { await api.post(`/api/agents/${agent.id}/commands`, { type, args: alertId ? { alert_id: alertId } : {} }); }
    finally { setBusy(false); }
  };

  if (iso.inflight) {
    return (
      <span className={`${h} flex items-center gap-2 rounded-md border border-line text-text-2`}>
        {spin} {iso.inflight === "isolate_host" ? "Isolating…" : "Releasing…"}
      </span>
    );
  }
  if (iso.isolated) {
    return (
      <button onClick={() => send("release_host")} disabled={busy || !online} className={outline}
        title="Remove the isolation firewall rules and restore normal networking">
        Release from isolation
      </button>
    );
  }
  if (confirm) {
    return (
      <span className="flex items-center gap-2">
        <span className="text-xs text-text-2">Cut {agent.hostname} off the network? The console stays reachable.</span>
        <button onClick={() => send("isolate_host")}
          className={`${h} rounded-md bg-crit font-medium text-white hover:brightness-110`}>Isolate</button>
        <button onClick={() => setConfirm(false)} className={outline}>Cancel</button>
      </span>
    );
  }
  return (
    <button onClick={() => setConfirm(true)} disabled={busy || !online}
      title={iso.failed ? `Last attempt failed: ${iso.failed.result?.error || "unknown error"}` : "Block all network traffic except to this console"}
      className={`${outline} hover:!border-crit/50 hover:!text-crit`}>
      {iso.failed ? "Isolate host (retry)" : "Isolate host"}
    </button>
  );
}

/** A red strip that says the machine is quarantined, and what still gets through. */
export function IsolationBanner({ agent, cmdLog, className = "" }) {
  const iso = useIsolation(agent, cmdLog);
  if (!iso.isolated) return null;
  return (
    <div role="status" className={`flex items-center gap-2.5 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-xs text-text ${className}`}>
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.8" className="shrink-0 text-crit" aria-hidden="true">
        <rect x="5" y="11" width="14" height="9" rx="1.5" /><path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </svg>
      <span>
        <span className="font-medium text-crit">Network isolated</span>
        {iso.since && <> since <span className="font-mono">{fmtTime(iso.since.toISOString()).slice(0, 8)}</span></>}
        . All traffic is blocked except to this console
        {iso.consoleIps.length > 0 && <> (<span className="font-mono">{iso.consoleIps.join(", ")}</span>)</>}.
      </span>
    </div>
  );
}
