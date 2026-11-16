import { IsolateControl } from "./Isolation.jsx";
import { useEffect, useMemo, useRef, useState } from "react";
import { caseNo, api, ago, basename, eventCategory, fmtTime, sevStyle, statusStyle, catStyle } from "../lib/live.js";
import AttackStory from "./AttackStory.jsx";
import KillSwitch from "./KillSwitch.jsx";
import ProcessGraph from "./ProcessGraph.jsx";
import Inspector from "./Inspector.jsx";
import Analyst from "./Analyst.jsx";

export function SeverityMark({ sev, withLabel = true }) {
  const s = sevStyle(sev);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: s.color }}>
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
        {sev === "critical" ? <path d="M5 0 10 5 5 10 0 5z" fill="currentColor" />
          : sev === "high" ? <path d="M5 1 9.5 9h-9z" fill="currentColor" />
          : <circle cx="5" cy="5" r="4" fill="currentColor" />}
      </svg>
      {withLabel && s.label}
    </span>
  );
}

export function StatusMark({ status }) {
  const s = statusStyle(status);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: status === "open" ? "var(--color-text-2)" : s.color }}>
      <span className={`h-1.5 w-1.5 rounded-full ${status === "open" ? "border border-text-2" : ""}`} style={{ background: status === "open" ? "transparent" : s.color }} />
      {s.label}
    </span>
  );
}

const actorOf = (a) => {
  const c = a.context || {};
  return basename(c.SourceImage || c.Image || "") || (c.ScriptBlockText ? "Script block" : c.TargetUserName || c.SubjectUserName || "");
};

// ------------------------------------------------------------------ queue

export function IncidentQueue({ incidents, selectedId, onSelect }) {
  const listRef = useRef(null);
  useEffect(() => {
    listRef.current?.querySelector(`[data-id="${selectedId}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  if (!incidents.length) {
    return (
      <div className="grid flex-1 place-items-center px-8 text-center">
        <div>
          <p className="font-medium">No cases</p>
          <p className="mt-1 text-xs text-muted">A case opens when a rule fires.</p>
        </div>
      </div>
    );
  }
  return (
    <ul ref={listRef} className="flex-1 overflow-y-auto" role="listbox" aria-label="Cases">
      {incidents.map((inc) => {
        const s = sevStyle(inc.severity);
        const on = selectedId === inc.id;
        const done = inc.status === "closed" || inc.status === "contained";
        const n = inc.alerts.length;
        return (
          <li key={inc.id} data-id={inc.id} role="option" aria-selected={on} onClick={() => onSelect(inc)}
            style={{ "--sev": s.color }}
            className={`relative cursor-pointer border-b border-line-soft px-4 py-3 transition-colors ${inc._new ? "row-alert" : ""} ${on ? "bg-raised" : "hover:bg-surface"}`}>
            <span className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: done ? "var(--color-line)" : s.color }} />
            <div className="flex items-center gap-3">
              <SeverityMark sev={inc.severity} />
              {n > 1 && <span className="rounded bg-line px-1.5 text-[11px] tabular-nums text-text-2">{n} alerts</span>}
              <span className="ml-auto text-xs text-muted" title={fmtTime(inc.last_ts)}>{ago(inc.last_ts)}</span>
            </div>
            <div className={`mt-1 truncate font-medium ${done ? "text-text-2" : ""}`} title={inc.title}>{inc.title}</div>
            <div className="mt-1 flex items-center gap-3 text-xs text-muted">
              <span className="truncate text-text-2">{inc.hostname}</span>
              {actorOf(inc.primary) && <span className="truncate font-mono">{actorOf(inc.primary)}</span>}
              <span className="ml-auto shrink-0"><StatusMark status={inc.status} /></span>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ------------------------------------------------------------------ detail

const FIELD_LABELS = {
  Image: "Process", CommandLine: "Command line", ParentImage: "Parent", ParentCommandLine: "Parent command line",
  User: "User", ProcessId: "PID", SourceImage: "Source process", SourceProcessId: "Source PID",
  TargetImage: "Target process", TargetObject: "Registry key", Details: "Value", TargetFilename: "File",
  TargetUserName: "Target user", SubjectUserName: "Actor", IpAddress: "Source IP", TaskName: "Task",
  ServiceName: "Service", MemberName: "Member", ScriptBlockText: "Script", QueryName: "Domain",
  DestinationIp: "Destination IP", DestinationPort: "Destination port", ProcessGuid: "Process GUID",
  GrantedAccess: "Granted access",
};

function Section({ title, aside, children }) {
  return (
    <section className="border-t border-line-soft px-6 py-5">
      <div className="mb-3 flex items-baseline gap-2">
        <h3 className="text-[13px] font-semibold">{title}</h3>
        {aside && <span className="text-xs text-muted">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

function Meta({ label, value }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5 truncate">{value}</dd>
    </div>
  );
}

const duration = (a, b) => {
  const s = Math.max(0, (Date.parse(b) - Date.parse(a)) / 1000);
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
};

/** Commands sent for one alert: REST on open, then live over the socket. */
export function useAlertCommands(alert, cmdLog) {
  const [fetched, setFetched] = useState([]);
  useEffect(() => {
    setFetched([]);
    if (alert) api.get(`/api/alerts/${alert.id}/commands`).then((r) => Array.isArray(r) && setFetched(r));
  }, [alert?.id, alert?.status]);
  return useMemo(() => {
    if (!alert) return [];
    const m = new Map(fetched.map((c) => [c.id, c]));
    for (const c of Object.values(cmdLog)) if (c.args?.alert_id === alert.id) m.set(c.id, { ...m.get(c.id), ...c });
    return [...m.values()].sort((a, b) => a.id - b.id);
  }, [fetched, cmdLog, alert?.id]);
}

export function IncidentDetail({ incident, alert, onSelectAlert, agents, cmdLog, onUpdate, onOpenEvent }) {
  const [events, setEvents] = useState([]);
  const [tree, setTree] = useState(undefined);
  const [busy, setBusy] = useState(null);
  const [picked, setPicked] = useState(null); // graph item under the inspector
  const cmds = useAlertCommands(alert, cmdLog);

  useEffect(() => {
    setEvents([]);
    setTree(undefined);
    setPicked(null);
    if (!alert) return;
    api.get(`/api/alerts/${alert.id}`).then((a) => setEvents(a.events || []));
    api.get(`/api/alerts/${alert.id}/tree`).then((t) => setTree(t?.root ? t : null)).catch(() => setTree(null));
  }, [alert?.id]);

  if (!incident || !alert) {
    return <div className="grid flex-1 place-items-center text-center text-muted"><p>Pick a case.</p></div>;
  }

  const ctx = alert.context || {};
  const pid = ctx.SourceProcessId || ctx.ProcessId;
  const procName = basename(ctx.SourceImage || ctx.Image || "") || "process";
  const agent = agents[alert.agent_id];
  const kills = cmds.filter((c) => c.type === "kill_process");
  const contained = alert.status === "contained" || kills.some((c) => c.status === "done");
  const lastDone = kills.filter((c) => c.status === "done").at(-1);
  const inflight = kills.some((c) => c.status === "pending" || c.status === "sent");
  const multi = incident.alerts.length > 1;

  const setStatus = async (status, ids = [alert.id]) => {
    setBusy(status);
    try {
      for (const id of ids) onUpdate(await api.patch(`/api/alerts/${id}`, { status }));
    } finally { setBusy(null); }
  };
  const kill = async () => {
    setBusy("kill");
    try {
      await api.post(`/api/agents/${alert.agent_id}/commands`, { type: "kill_process", args: { pid: Number(pid), alert_id: alert.id } });
    } finally { setBusy(null); }
  };
  const unresolved = incident.alerts.filter((a) => a.status !== "closed").map((a) => a.id);

  return (
    <div className="flex min-w-0 flex-1 flex-col">
      <div className="flex-1 overflow-y-auto">
       <div className="min-[1380px]:grid min-[1380px]:grid-cols-[minmax(0,1fr)_340px]">
       <div className="min-w-0">
        {/* incident header: no box, the facts sit on the page */}
        <header className="relative px-6 pb-5 pt-4">
          <span className="absolute left-0 top-0 h-full w-[3px]" style={{ background: contained ? "var(--color-ok)" : sevStyle(incident.severity).color }} />
          <div className="flex items-center gap-3 text-xs">
            <SeverityMark sev={incident.severity} />
            <StatusMark status={incident.status} />
            <span className="ml-auto font-mono font-medium text-text">{caseNo(incident.id)}</span>
          </div>
          <div className="mt-2 flex items-start gap-6">
            <div className="min-w-0 flex-1">
              <h2 className="font-cond text-[26px] font-semibold leading-[1.1] tracking-[-0.01em] xl:text-[30px]">{incident.title}</h2>
              {!multi && <p className="mt-2 max-w-[64ch] text-text-2">{alert.description}</p>}
            </div>
            {lastDone && (
              <div className="shrink-0 text-right">
                <div className="font-cond text-[26px] font-semibold leading-none text-ok xl:text-[30px]">{fmtSecs(secs(lastDone.created_at, lastDone.completed_at))}</div>
                <div className="mt-1 text-xs text-muted">click to kill</div>
              </div>
            )}
          </div>

          <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-3">
            <Meta label="Endpoint" value={<>{incident.hostname}{agent?.ip && <span className="ml-1.5 font-mono text-xs text-muted">{agent.ip}</span>}</>} />
            <Meta label={multi ? "First seen" : "Detected"} value={<span title={incident.first_ts}>{fmtTime(incident.first_ts).slice(0, 8)} <span className="text-muted">{ago(incident.first_ts)}</span></span>} />
            {multi
              ? <Meta label="Active for" value={duration(incident.first_ts, incident.last_ts)} />
              : <Meta label="Tactic" value={alert.tactic} />}
            <Meta label={incident.techniques.length > 1 ? "Techniques" : "MITRE ATT&CK"} value={
              <span className="flex gap-2">
                {incident.techniques.map((t) => (
                  <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                    className="hover:text-accent hover:underline" title={t.name}>
                    <span className="font-mono">{t.id}</span>{incident.techniques.length === 1 && <span className="text-text-2"> {t.name.split(": ").pop()}</span>}
                  </a>
                ))}
              </span>
            } />
          </dl>
        </header>

        {multi && (
          <Section title="Alerts" aside={`${incident.alerts.length}, newest first`}>
            <ol className="-mx-2">
              {incident.alerts.map((a) => {
                const on = a.id === alert.id;
                return (
                  <li key={a.id}>
                    <button onClick={() => onSelectAlert(a.id)} aria-current={on}
                      className={`grid w-full grid-cols-[72px_76px_1fr_auto] items-center gap-3 rounded-md px-2 py-1.5 text-left ${on ? "bg-raised" : "hover:bg-surface"}`}>
                      <span className="font-mono text-xs text-muted">{fmtTime(a.ts).slice(0, 8)}</span>
                      <SeverityMark sev={a.severity} />
                      <span className="truncate">
                        <span className={on ? "font-medium" : "text-text-2"}>{a.rule_title}</span>
                        <span className="ml-2 font-mono text-xs text-muted">{a.technique}</span>
                      </span>
                      <StatusMark status={a.status} />
                    </button>
                  </li>
                );
              })}
            </ol>
          </Section>
        )}

        <div className="border-t border-line-soft px-6 py-5"><Analyst alert={alert} tree={tree} kills={kills} /></div>

        {alert.rule_id === "IMP-002" && <Section title="Ransomware kill-switch"><KillSwitch alert={alert} /></Section>}

        <Section title={tree ? "Process graph" : "Attack story"} aside={tree === undefined ? "Rebuilding from telemetry…" : tree ? null : "Reconstructed from the triggering event"}>
          {tree
            ? <ProcessGraph tree={tree} alert={alert} terminated={contained} killCmd={lastDone}
                selectedKey={picked?.key} onSelect={(x) => setPicked(picked?.key === x.key ? null : x)} />
            : <AttackStory alert={alert} terminated={contained} />}
        </Section>

        <div className="border-t border-line-soft px-6 py-5 min-[1380px]:hidden">
          <h3 className="mb-4 text-[13px] font-semibold">Evidence</h3>
          <Inspector alert={alert} tree={tree} kills={kills} selected={picked} onOpenEvent={onOpenEvent} />
        </div>

        {kills.length > 0 && (
          <Section title="Response" aside={`${kills.length} action${kills.length === 1 ? "" : "s"} on ${alert.hostname}`}>
            <div className="space-y-5">{kills.map((c) => <ResponseTimeline key={c.id} cmd={c} />)}</div>
          </Section>
        )}

        <Section title="Evidence" aside={`${alert.event_ids.length} raw event${alert.event_ids.length === 1 ? "" : "s"}`}>
          <div className="overflow-hidden rounded-lg border border-line">
            {events.length === 0 && <div className="px-3 py-2.5 text-xs text-muted">Loading events…</div>}
            {events.map((e) => (
              <button key={e.id} onClick={() => onOpenEvent(e)}
                className="flex w-full items-start gap-3 border-b border-line-soft px-3 py-2 text-left text-xs last:border-0 hover:bg-surface">
                <span className="shrink-0 font-mono text-muted">{fmtTime(e.ts)}</span>
                <span className="w-20 shrink-0" style={{ color: catStyle(eventCategory(e)).color }}>{catStyle(eventCategory(e)).label}</span>
                <span className="min-w-0 break-all font-mono text-text-2">{e.summary}</span>
              </button>
            ))}
          </div>
        </Section>

        <details className="group border-t border-line-soft px-6 py-4">
          <summary className="flex cursor-pointer list-none items-center gap-2 text-[13px] font-semibold [&::-webkit-details-marker]:hidden">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" className="text-muted transition-transform group-open:rotate-90" aria-hidden="true"><path d="m9 6 6 6-6 6" /></svg>
            Raw fields
            <span className="text-xs font-normal text-muted">{Object.keys(ctx).length} fields from the triggering event</span>
          </summary>
          <dl className="mt-3 grid grid-cols-[150px_1fr] gap-x-4 gap-y-2 text-xs">
            {Object.entries(ctx).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{FIELD_LABELS[k] || k}</dt>
                <dd className="max-h-32 overflow-y-auto break-all font-mono text-text-2">{String(v)}</dd>
              </div>
            ))}
          </dl>
        </details>
       </div>
       <aside className="hidden border-l border-line-soft min-[1380px]:block" aria-label="Evidence">
         <div className="sticky top-0 max-h-full overflow-y-auto px-5 py-5">
           <h3 className="mb-4 font-cond text-[17px] font-semibold">Evidence</h3>
           <Inspector alert={alert} tree={tree} kills={kills} selected={picked} onOpenEvent={onOpenEvent} />
         </div>
       </aside>
       </div>
      </div>

      {/* response bar */}
      <footer className="flex shrink-0 items-center gap-2 border-t border-line bg-surface px-6 py-3">
        {pid && (contained ? (
          <span className="flex items-center gap-2 text-sm text-ok">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>
            {procName} (PID {pid}) killed on {alert.hostname}
          </span>
        ) : (
          <button onClick={kill} disabled={!!busy || inflight}
            className="flex h-8 items-center gap-2 rounded-md bg-crit px-3.5 text-[13px] font-medium text-white transition hover:brightness-110 disabled:cursor-wait disabled:opacity-60">
            {inflight ? (
              <><span className="h-3 w-3 animate-spin rounded-full border-2 border-white/40 border-t-white" /> Killing {procName}…</>
            ) : (
              <>{kills.some((c) => c.status === "failed" || c.status === "expired") ? "Retry kill" : "Kill"} {procName} <span className="font-mono text-xs text-white/75">PID {pid}</span></>
            )}
          </button>
        ))}
        <div className="ml-auto flex gap-2">
          <IsolateControl agent={agent} cmdLog={cmdLog} alertId={alert.id} />
          {incident.status === "open" && (
            <button onClick={() => setStatus("acknowledged", incident.alerts.filter((a) => a.status === "open").map((a) => a.id))} disabled={!!busy}
              className="h-8 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text disabled:opacity-50">
              Take case
            </button>
          )}
          {unresolved.length ? (
            <button onClick={() => setStatus("closed", unresolved)} disabled={!!busy}
              className="h-8 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text disabled:opacity-50">
              Close case
            </button>
          ) : (
            <button onClick={() => setStatus("open", incident.alerts.map((a) => a.id))} disabled={!!busy}
              className="h-8 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text disabled:opacity-50">
              Reopen case
            </button>
          )}
        </div>
      </footer>
    </div>
  );
}

// ------------------------------------------------------------------ response timeline

const secs = (a, b) => (a && b ? (Date.parse(b) - Date.parse(a)) / 1000 : null);
const fmtSecs = (s) => (s == null ? "" : s < 10 ? `${s.toFixed(2)} s` : `${s.toFixed(1)} s`);

/** Queued → delivered → terminated, with the time each hop took. */
function ResponseTimeline({ cmd }) {
  const { status } = cmd;
  const delivered = status !== "pending" && status !== "expired";
  const finished = status === "done" || status === "failed";
  const total = secs(cmd.created_at, cmd.completed_at);
  const steps = [
    { label: "Queued", sub: fmtTime(cmd.created_at), state: "done" },
    {
      label: status === "expired" ? "Not collected" : "Delivered to agent",
      sub: status === "expired" ? "Agent was offline for 60 s" : cmd.sent_at ? `+${fmtSecs(secs(cmd.created_at, cmd.sent_at))}` : delivered ? "" : "Waiting for agent check-in",
      state: status === "expired" ? "fail" : delivered ? "done" : "active",
    },
    {
      label: status === "failed" ? "Failed" : "Process terminated",
      sub: status === "failed"
        ? (/not found/i.test(cmd.result?.output || "") ? "Process had already exited"
          : String(cmd.result?.error || cmd.result?.output || "The agent reported an error").slice(0, 120))
        : finished ? `+${fmtSecs(total)}` : "",
      state: status === "done" ? "done" : status === "failed" ? "fail" : status === "sent" ? "active" : "todo",
    },
  ];
  const color = { done: "var(--color-ok)", fail: "var(--color-crit)", active: "var(--color-accent)", todo: "var(--color-line)" };

  return (
    <div>
      <div className="flex items-baseline gap-3">
        <span className="font-medium">Kill PID {cmd.args?.pid}</span>
        {status === "done" && total != null && (
          <span className="text-ok">Contained in <span className="font-semibold tabular-nums">{fmtSecs(total)}</span></span>
        )}
        {status === "failed" && <span className="text-crit">Action failed</span>}
        {status === "expired" && <span className="text-crit">Action expired</span>}
        {(status === "pending" || status === "sent") && <span className="text-accent">In progress</span>}
      </div>
      <ol className="mt-3 grid grid-cols-3">
        {steps.map((s, i) => (
          <li key={i} className="relative">
            <div className="flex items-center">
              <span className={`relative z-10 h-2.5 w-2.5 shrink-0 rounded-full ${s.state === "active" ? "live-ring" : ""}`}
                style={{ background: s.state === "todo" ? "transparent" : color[s.state], border: `2px solid ${color[s.state]}`, color: color[s.state] }} />
              {i < steps.length - 1 && (
                <span className="h-[2px] flex-1" style={{ background: steps[i + 1].state === "todo" ? "var(--color-line)" : color[steps[i + 1].state === "fail" ? "fail" : "done"] }} />
              )}
            </div>
            <div className={`mt-2 pr-4 text-xs ${s.state === "todo" ? "text-muted" : "text-text"}`}>{s.label}</div>
            <div className={`mt-0.5 pr-4 font-mono text-xs ${s.state === "fail" ? "text-crit" : "text-muted"}`}>{s.sub}</div>
          </li>
        ))}
      </ol>
    </div>
  );
}

// ------------------------------------------------------------------ toasts

export function AlertToasts({ toasts, onOpen, onDismiss }) {
  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-50 flex w-[360px] max-w-[calc(100vw-2.5rem)] flex-col-reverse gap-2" aria-live="polite">
      {toasts.map((a) => {
        const s = sevStyle(a.severity);
        return (
          <div key={a.id} role="button" tabIndex={0}
            className="toast-in pointer-events-auto relative cursor-pointer overflow-hidden rounded-lg border border-line bg-raised py-3 pl-4 pr-3 shadow-[0_12px_40px_rgb(0_0_0/0.5)]"
            onClick={() => { onOpen(a); onDismiss(a.id); }}
            onKeyDown={(e) => e.key === "Enter" && (onOpen(a), onDismiss(a.id))}>
            <span className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: s.color }} />
            <div className="flex items-center gap-2 text-xs">
              <SeverityMark sev={a.severity} />
              <span className="text-muted">on {a.hostname}</span>
              <button onClick={(e) => { e.stopPropagation(); onDismiss(a.id); }} className="ml-auto px-1 text-muted hover:text-text" aria-label="Dismiss">×</button>
            </div>
            <div className="mt-1 font-medium">{a.rule_title}</div>
            <div className="mt-0.5 truncate font-mono text-xs text-muted">{a.title}</div>
          </div>
        );
      })}
    </div>
  );
}
