import { useEffect, useState } from "react";
import { api, fmtTime, isOnline } from "../lib/live.js";
import JudgeMode from "./JudgeMode.jsx";

export async function runValidation(agents, test = "encoded_powershell") {
  const target = Object.values(agents).filter(isOnline).sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""))[0];
  if (!target) return { error: "No endpoint is reporting. Start the agent on the VM first." };
  return api.post("/api/validation/run", { agent_id: target.id, test });
}

const plus = (a, b) => (a && b ? `+${((Date.parse(b) - Date.parse(a)) / 1000).toFixed(2)} s` : "");

/** "Test my protection": fire a harmless simulation and watch every stage catch it. */
export default function Verify({ agents, kick, onOpenAlert }) {
  const [tests, setTests] = useState([]);
  const [test, setTest] = useState("encoded_powershell");
  const [run, setRun] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.get("/api/validation/tests").then((t) => Array.isArray(t) && setTests(t)); }, []);

  const refresh = () => api.get("/api/validation/latest").then((v) => setRun(v?.id ? v : null)).catch(() => {});
  useEffect(() => { refresh(); }, [kick]);
  useEffect(() => {
    const id = setInterval(refresh, run?.status === "running" ? 800 : 5000);
    return () => clearInterval(id);
  }, [run?.status]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const v = await runValidation(agents, test);
      if (v.error || v.detail) setError(v.error || v.detail);
      else setRun(v);
    } finally { setBusy(false); }
  };

  const status = run?.status;
  const spec = tests.find((t) => t.id === test);
  const failed = run?.steps.find((s) => s.state === "fail");
  const color = { done: "var(--color-ok)", fail: "var(--color-crit)", active: "var(--color-accent)", todo: "var(--color-line)" };

  return (
    <div className="flex flex-1 flex-col">
      <div className="flex items-start gap-3">
        <div className="min-w-0">
          <h2 className="font-cond text-[19px] font-semibold leading-tight">Detection drill</h2>
        </div>
        <div className="ml-auto"><JudgeMode agents={agents} /></div>
        <span className="mt-1.5 shrink-0 rounded-full border px-2.5 py-0.5 text-xs"
          style={{
            borderColor: status === "passed" ? "var(--color-ok)" : status === "failed" ? "var(--color-crit)" : status === "running" ? "var(--color-accent)" : "var(--color-line)",
            color: status === "passed" ? "var(--color-ok)" : status === "failed" ? "var(--color-crit)" : status === "running" ? "var(--color-accent)" : "var(--color-muted)",
          }}>
          {status === "passed" ? `Passed, ${run.seconds.toFixed(2)} s` : status === "failed" ? "Failed" : status === "running" ? "Running" : "Never run"}
        </span>
      </div>

      {/* stage stepper, centred in whatever height the panel has */}
      <div className="flex flex-1 flex-col justify-center">
      <ol className="mt-5 grid grid-cols-4">
        {(run?.steps || [{ label: "Drill ran" }, { label: "Event received" }, { label: "Rule fired" }, { label: "Case opened" }]).map((s, i, arr) => {
          const st = s.state || "todo";
          const next = arr[i + 1]?.state || "todo";
          return (
            <li key={i} className="relative">
              <div className="flex items-center">
                <span className={`relative z-10 grid h-7 w-7 shrink-0 place-items-center rounded-full border-2 text-xs font-semibold ${st === "active" ? "live-ring" : ""}`}
                  style={{ borderColor: color[st], color: st === "done" ? "var(--color-bg)" : color[st] === "var(--color-line)" ? "var(--color-muted)" : color[st],
                    background: st === "done" ? color.done : "var(--color-bg)" }}>
                  {st === "done" ? <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="m2.5 6.2 2.3 2.3 4.7-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
                    : st === "fail" ? "!" : i + 1}
                </span>
                {i < arr.length - 1 && <span className="h-[2px] flex-1" style={{ background: next === "todo" ? "var(--color-line)" : color[next === "fail" ? "fail" : "done"] }} />}
              </div>
              <div className={`mt-2 pr-2 text-xs ${st === "todo" ? "text-muted" : "text-text"}`}>{s.label}</div>
              <div className="pr-2 font-mono text-[11px] text-muted">
                {st === "done" ? (i === 0 ? fmtTime(s.at).slice(0, 8) : plus(run.started_at, s.at)) : st === "active" ? "waiting" : st === "fail" ? "missing" : s.sub || ""}
              </div>
            </li>
          );
        })}
      </ol>

      <div className="mt-4 text-xs">
        {error ? <p className="text-crit">{error}</p>
          : status === "passed" ? <p className="text-text-2"><span className="text-ok">Caught.</span> {run.spec.rule_id} fired in {run.seconds.toFixed(2)} s.</p>
          : status === "failed" ? <p className="text-text-2"><span className="text-crit">{failed?.label} failed.</span> {failed?.detail}</p>
          : status === "running" ? <p className="text-text-2">Running {run.spec.title.toLowerCase()} on the endpoint…</p>
          : <p className="text-muted">{spec?.description}</p>}
      </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-md border border-line bg-surface p-0.5" role="radiogroup" aria-label="Test to run">
          {tests.map((t) => (
            <button key={t.id} role="radio" aria-checked={test === t.id} onClick={() => setTest(t.id)} title={t.description}
              className={`rounded px-2.5 py-1 text-xs ${test === t.id ? "bg-raised text-text" : "text-muted hover:text-text-2"}`}>{t.title}</button>
          ))}
        </div>
        <div className="ml-auto flex gap-2">
          {status === "passed" && run.steps[2].alert_id && (
            <button onClick={() => onOpenAlert(run.steps[2].alert_id)}
              className="h-8 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text">Open case</button>
          )}
          <button onClick={start} disabled={busy || status === "running"}
            className="flex h-8 items-center gap-2 rounded-md bg-accent px-3.5 text-[13px] font-medium text-bg transition hover:brightness-110 disabled:opacity-60">
            <svg width="10" height="10" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 1.5v9l7.5-4.5z" fill="currentColor" /></svg>
            {status === "running" ? "Running…" : run ? "Run again" : "Run drill"}
          </button>
        </div>
      </div>
    </div>
  );
}
