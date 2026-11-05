import { useEffect, useMemo, useState } from "react";
import { api, ago, fmtTime } from "../lib/live.js";

const STATUS = {
  installing: { label: "Installing", color: "var(--color-accent)" },
  online: { label: "Checking in", color: "var(--color-accent)" },
  protected: { label: "Protected", color: "var(--color-ok)" },
  failed: { label: "Failed", color: "var(--color-crit)" },
  removed: { label: "Removed", color: "var(--color-muted)" },
};
const FALLBACK_STEPS = [
  ["connect", "Reached the console"], ["runtime", "Agent runtime installed"], ["enroll", "Endpoint enrolled"],
  ["sysmon", "Sysmon telemetry"], ["audit", "Audit and script logging"], ["service", "Agent service started"],
  ["online", "First heartbeat"], ["telemetry", "First events received"],
].map(([id, label]) => ({ id, label }));

const STEP_COLOR = { done: "var(--color-ok)", skip: "var(--color-med)", fail: "var(--color-crit)", active: "var(--color-accent)", todo: "var(--color-line)" };
const finished = (state) => state === "done" || state === "skip";
// the public download page (landing/), set at build time once it is deployed: VITE_AEGIS_DOWNLOAD_URL=https://…
const DOWNLOAD_URL = import.meta.env.VITE_AEGIS_DOWNLOAD_URL || "";
const secs = (a, b) => Math.max(0, (Date.parse(b) - Date.parse(a)) / 1000);
const fmtSecs = (s) => (s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`);

/** "Add endpoint": the one-line installer and a live view of every enrollment in flight. */
export default function Onboarding({ installs, requests = {}, onOpenHost, onClose }) {
  const [info, setInfo] = useState(null);
  const [addr, setAddr] = useState(null);
  const [copied, setCopied] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [showManual, setShowManual] = useState(false);
  const [auto, setAuto] = useState(false);
  useEffect(() => { if (info && "auto_approve" in info) setAuto(info.auto_approve); }, [info]);
  const toggleAuto = async () => {
    const r = await api.post("/api/enroll/auto_approve", { on: !auto }).catch(() => null);
    if (r) setAuto(r.auto_approve);
  };
  const waiting = Object.values(requests)
    .filter((r) => r.status === "pending" && Date.now() - Date.parse(r.created_at) < 600_000)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  useEffect(() => { api.get("/api/enroll/info").then(setInfo).catch(() => setInfo({ error: true })); }, []);

  // default address: the one this browser already uses, unless that is localhost
  const addresses = useMemo(() => {
    const list = info?.addresses || [];
    const here = location.hostname;
    if (here !== "localhost" && here !== "127.0.0.1" && !list.some((a) => a.url.includes(`//${here}:`))) {
      return [{ url: location.origin, label: "This address", iface: "browser" }, ...list];
    }
    return list;
  }, [info]);
  const chosen = addr || addresses.find((a) => a.url === location.origin)?.url || addresses[0]?.url;
  const command = info?.token && chosen ? `irm ${chosen}/install.ps1?t=${info.token} | iex` : "";

  const copy = async () => {
    try { await navigator.clipboard.writeText(command); }
    catch {
      const el = document.getElementById("enroll-cmd");
      if (el) { const r = document.createRange(); r.selectNodeContents(el); getSelection().removeAllRanges(); getSelection().addRange(r); }
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  const rotate = async () => {
    const r = await api.post("/api/enroll/rotate", {});
    setInfo((i) => ({ ...i, token: r.token }));
    setConfirmRotate(false);
  };

  // runs worth showing: anything from the last hour, newest first
  const runs = Object.values(installs)
    .filter((i) => i.status !== "removed" && Date.now() - Date.parse(i.updated_at || i.started_at) < 3600_000)
    .sort((a, b) => b.started_at.localeCompare(a.started_at))
    .slice(0, 4);
  const steps = info?.steps || FALLBACK_STEPS;

  return (
    <section className="border-b border-line bg-surface/60" aria-label="Add endpoint">
      <div className="grid gap-x-10 gap-y-6 px-6 py-5 min-[1180px]:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {/* ---- left: how to enroll */}
        <div className="min-w-0">
          <div className="flex items-baseline gap-3">
            <h2 className="font-cond text-[19px] font-semibold leading-tight">Enroll a Windows endpoint</h2>
            {onClose && <button onClick={onClose} className="ml-auto text-xs text-muted hover:text-text">Close</button>}
          </div>
          <p className="mt-1 max-w-[60ch] text-[13px] text-text-2">
            Any Windows 10 or 11 machine on this network. Aegis Setup finds this console by itself;
            the console serves everything else the installer needs.
          </p>

          <ol className="mt-4 space-y-4 text-[13px]">
            <li className="flex gap-3">
              <Num n={1} />
              <div className="min-w-0 flex-1">
                <p>
                  On the laptop, download and run <b className="font-semibold">Aegis Setup</b>
                  {DOWNLOAD_URL
                    ? <> from <a href={DOWNLOAD_URL} target="_blank" rel="noreferrer" className="font-medium text-accent hover:underline">{DOWNLOAD_URL.replace(/^https?:\/\//, "").replace(/\/$/, "")}</a></>
                    : <> from the Aegis download page</>}.
                </p>
                <p className="mt-0.5 text-xs text-muted">It looks for this console on the local network. No address or code to type.</p>
              </div>
            </li>
            <li className="flex gap-3">
              <Num n={2} />
              <div className="min-w-0 flex-1">
                <p>Approve the machine here when it asks to join.</p>
                <label className="mt-1.5 inline-flex cursor-pointer select-none items-center gap-2 text-xs text-text-2">
                  <button role="switch" aria-checked={auto} onClick={toggleAuto}
                    className={`relative h-[16px] w-[28px] shrink-0 rounded-full border transition-colors ${auto ? "border-accent bg-accent" : "border-line bg-raised"}`}>
                    <span className={`absolute top-[2px] h-[10px] w-[10px] rounded-full transition-all ${auto ? "left-[14px] bg-bg" : "left-[2px] bg-muted"}`} />
                  </button>
                  Approve every machine automatically
                  {auto && <span className="text-warn">· anyone on this network can enroll</span>}
                </label>
              </div>
            </li>
            <li className="flex gap-3">
              <Num n={3} />
              <div className="min-w-0 flex-1">
                <p>Watch it come online here. It takes about half a minute.</p>
              </div>
            </li>
          </ol>

          <div className="mt-4 text-xs">
            <button onClick={() => setShowManual((v) => !v)} className="text-muted hover:text-text-2 hover:underline" aria-expanded={showManual}>
              {showManual ? "Hide the manual command" : "No download? Paste one line instead"}
            </button>
            {showManual && (
              <div className="mt-2 max-w-[640px]">
                <p className="text-[13px] text-text-2">In <b className="font-semibold">Terminal (Admin)</b> on the laptop <span className="text-muted">(Win + X, then A)</span>. No approval needed: the token is in the command.</p>
                {info?.error ? (
                  <p className="mt-2 text-crit">Could not load enrollment details from the backend.</p>
                ) : (
                  <div className="mt-2 flex items-stretch overflow-hidden rounded-md border border-line bg-bg">
                    <code id="enroll-cmd" className="min-w-0 flex-1 select-all overflow-x-auto whitespace-nowrap px-3 py-2.5 font-mono text-[12.5px] text-text">
                      {command || "loading…"}
                    </code>
                    <button onClick={copy} disabled={!command}
                      className={`shrink-0 border-l border-line px-3.5 text-xs font-medium transition-colors ${copied ? "bg-ok text-bg" : "bg-accent text-bg hover:brightness-110"}`}>
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                )}
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-muted">
                  {addresses.length > 1 && (
                    <span className="flex items-center gap-1.5">
                      Console address
                      <span className="inline-flex rounded-md border border-line bg-surface p-0.5">
                        {addresses.map((a) => (
                          <button key={a.url} onClick={() => setAddr(a.url)} title={a.url}
                            className={`rounded px-2 py-0.5 ${chosen === a.url ? "bg-raised text-text" : "hover:text-text-2"}`}>{a.label}</button>
                        ))}
                      </span>
                    </span>
                  )}
                  {confirmRotate ? (
                    <span className="flex items-center gap-2">
                      <span className="text-text-2">Old commands stop working.</span>
                      <button onClick={rotate} className="text-crit hover:underline">Issue new token</button>
                      <button onClick={() => setConfirmRotate(false)} className="hover:text-text">Cancel</button>
                    </span>
                  ) : (
                    <button onClick={() => setConfirmRotate(true)} className="hover:text-text-2 hover:underline">New token</button>
                  )}
                </div>
              </div>
            )}
            {info && info.payload_ready === false && (
              <p className="mt-2 text-warn">Installer files are missing on the console. Run <code className="font-mono">backend/fetch_payload.sh</code> once.</p>
            )}
          </div>

          <dl className="mt-5 grid max-w-[560px] grid-cols-3 gap-4 border-t border-line-soft pt-3 text-xs">
            <Fact k="Installs to" v="C:\Program Files\Aegis" mono />
            <Fact k="Runs as" v="SYSTEM, at startup" />
            <Fact k="Removal" v="One click, restores audit policy" />
          </dl>
        </div>

        {/* ---- right: live enrollments */}
        <div className="min-w-0">
          {waiting.length > 0 && (
            <div className="mb-5">
              <h3 className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-[0.08em] text-warn">
                <span className="live-ring h-1.5 w-1.5 rounded-full bg-warn text-warn" />Asking to join
              </h3>
              <div className="mt-2 grid gap-2">
                {waiting.map((r) => <JoinRequest key={r.id} req={r} />)}
              </div>
            </div>
          )}
          <div className="flex items-baseline justify-between">
            <h3 className="text-xs font-medium uppercase tracking-[0.08em] text-muted">Enrollments</h3>
            {runs.some((r) => r.status === "installing" || r.status === "online") && (
              <span className="flex items-center gap-1.5 text-xs text-accent"><span className="live-ring h-1.5 w-1.5 rounded-full bg-accent text-accent" />live</span>
            )}
          </div>
          {runs.length === 0 ? (
            <div className="mt-3 grid min-h-[200px] place-items-center rounded-md border border-dashed border-line text-center">
              <div className="px-6">
                <p className="text-[13px] text-text-2">Waiting for a machine to run Aegis Setup</p>
                <p className="mt-1 text-xs text-muted">Each step shows up here the moment the installer reports it.</p>
              </div>
            </div>
          ) : (
            <div className="mt-3 grid gap-3">
              {runs.map((r, i) => <Run key={r.id} run={r} steps={steps} compact={i > 0} onOpenHost={onOpenHost} />)}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function JoinRequest({ req }) {
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(false);
  const decide = async (d) => {
    setBusy(d); setErr(false);
    try { await api.post(`/api/enroll/request/${req.id}/${d}`, {}); } // the socket update removes it from the list
    catch { setErr(true); setBusy(null); }
  };
  return (
    <article className="arrive flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-warn/50 bg-bg px-4 py-3">
      <div className="min-w-0 flex-1">
        <h4 className="truncate font-cond text-[17px] font-semibold leading-tight">{req.hostname || "Unknown host"}</h4>
        <p className="mt-0.5 truncate text-xs text-muted">
          {[req.user, req.os, req.arch, req.ip].filter(Boolean).join(" · ")} · asked {ago(req.created_at)}
        </p>
        {err && <p className="mt-1 text-xs text-crit">That request has expired. Ask them to run setup again.</p>}
      </div>
      <div className="flex shrink-0 gap-2">
        <button onClick={() => decide("deny")} disabled={!!busy}
          className="rounded-md border border-line px-3 py-1.5 text-xs text-text-2 hover:border-crit/60 hover:text-crit disabled:opacity-50">Decline</button>
        <button onClick={() => decide("approve")} disabled={!!busy}
          className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-medium text-bg hover:brightness-110 disabled:opacity-60">
          {busy === "approve" ? "Approving…" : "Approve"}
        </button>
      </div>
    </article>
  );
}

function Num({ n }) {
  return <span className="mt-px grid h-5 w-5 shrink-0 place-items-center rounded-full border border-text-2/50 font-cond text-[11px] font-semibold text-text-2">{n}</span>;
}

function Fact({ k, v, mono }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted">{k}</dt>
      <dd className={`mt-0.5 truncate text-text-2 ${mono ? "font-mono" : ""}`} title={v}>{v}</dd>
    </div>
  );
}

function Run({ run, steps, compact, onOpenHost }) {
  const [, tick] = useState(0);
  const active = run.status === "installing" || run.status === "online";
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => tick((n) => n + 1), 250);
    return () => clearInterval(id);
  }, [active]);

  const st = STATUS[run.status] || STATUS.installing;
  const end = run.status === "protected" ? run.steps.telemetry?.at : run.status === "failed" ? run.updated_at : new Date().toISOString();
  const elapsed = secs(run.started_at, end);
  const done = steps.filter((s) => finished(run.steps[s.id]?.state)).length;
  // the step in progress: the reported active one, else the first not yet done after the installer finished
  const current = steps.find((s) => run.steps[s.id]?.state === "active")?.id
    || (run.steps.service?.state === "done" ? steps.find((s) => !finished(run.steps[s.id]?.state))?.id : null);

  return (
    <article className={`arrive rounded-md border bg-bg ${run.status === "failed" ? "border-crit/50" : run.status === "protected" ? "border-ok/40" : "border-line"}`}>
      <header className="flex items-start gap-3 px-4 pb-2 pt-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="truncate font-cond text-[17px] font-semibold leading-tight">{run.hostname || "Unknown host"}</h4>
            <span className="shrink-0 rounded-full border px-2 py-px text-[11px]" style={{ borderColor: st.color, color: st.color }}>{st.label}</span>
          </div>
          <p className="mt-0.5 truncate text-xs text-muted">
            {[run.os, run.arch, run.user, run.ip].filter(Boolean).join(" · ")}
          </p>
        </div>
        <div className="ml-auto shrink-0 text-right">
          <div className="font-cond text-[22px] font-semibold tabular-nums leading-none" style={{ color: run.status === "protected" ? "var(--color-ok)" : undefined }}>
            {fmtSecs(elapsed)}
          </div>
          <div className="mt-0.5 text-[11px] text-muted">
            {run.status === "protected" ? "to full coverage" : run.status === "failed" ? "before it stopped" : `${done} of ${steps.length} steps`}
          </div>
        </div>
      </header>

      {/* progress bar: one segment per step */}
      <div className="flex gap-[3px] px-4" aria-hidden="true">
        {steps.map((s) => {
          const state = run.steps[s.id]?.state || (current === s.id ? "active" : "todo");
          return <span key={s.id} className={`h-1 flex-1 rounded-full ${state === "active" ? "animate-pulse" : ""}`}
            style={{ background: STEP_COLOR[state] || STEP_COLOR.todo }} />;
        })}
      </div>

      {compact && run.status === "protected" ? (
        <p className="px-4 py-2.5 text-xs text-text-2">Enrolled {ago(run.started_at)}.</p>
      ) : (
        <ol className="px-4 py-3">
          {steps.map((s, i) => {
            const rec = run.steps[s.id];
            const state = rec?.state || (current === s.id ? "active" : "todo");
            return (
              <li key={s.id} className="relative flex gap-3 pb-1.5 last:pb-0">
                {i < steps.length - 1 && (
                  <span className="absolute left-[7px] top-[17px] bottom-[-3px] w-px"
                    style={{ background: finished(state) ? STEP_COLOR[state] : "var(--color-line)" }} />
                )}
                <Dot state={state} />
                <div className="flex min-w-0 flex-1 items-baseline gap-3 text-[13px] leading-[18px]">
                  <span className={state === "todo" ? "text-muted" : state === "fail" ? "text-crit" : "text-text"}>{s.label}</span>
                  <span className={`min-w-0 flex-1 truncate text-xs ${state === "fail" ? "text-crit" : state === "skip" ? "text-warn" : "text-muted"}`} title={rec?.detail}>
                    {state === "active" ? "working…" : state === "skip" ? `skipped: ${rec?.detail}` : rec?.detail}
                  </span>
                  <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted">
                    {finished(state) && rec?.at ? `+${secs(run.started_at, rec.at).toFixed(1)}s` : ""}
                  </span>
                </div>
              </li>
            );
          })}
        </ol>
      )}

      {(run.status === "protected" || run.status === "online") && run.agent_id && (
        <footer className="flex items-center gap-3 border-t border-line-soft px-4 py-2 text-xs">
          <span className="text-muted">Started {fmtTime(run.started_at).slice(0, 8)}</span>
          <button onClick={() => onOpenHost?.(run.agent_id)} className="ml-auto font-medium text-accent hover:underline">Show host</button>
        </footer>
      )}
    </article>
  );
}

function Dot({ state }) {
  const c = STEP_COLOR[state] || STEP_COLOR.todo;
  return (
    <span className={`relative z-10 mt-[1px] grid h-[15px] w-[15px] shrink-0 place-items-center rounded-full border-[1.5px] ${state === "active" ? "live-ring" : ""}`}
      style={{ borderColor: c, background: state === "done" ? c : "var(--color-bg)", color: state === "active" ? c : "var(--color-bg)" }}>
      {state === "done" && <svg width="8" height="8" viewBox="0 0 12 12" aria-hidden="true"><path d="m2.5 6.2 2.3 2.3 4.7-5" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" /></svg>}
      {state === "skip" && <span className="h-[1.5px] w-[7px] rounded-full" style={{ background: c }} />}
      {state === "fail" && <span className="text-[9px] font-bold leading-none" style={{ color: c }}>!</span>}
    </span>
  );
}
