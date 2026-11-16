import { useEffect, useState } from "react";
import { api, fmtTime } from "../lib/live.js";

const FALLBACK = ["Simulation launched", "Telemetry received", "Detection rule fired", "Case opened"];

/** A compact, judge-friendly view of the real validation pipeline. */
export default function ProtectionProof({ agents, kick, onOpenAlert }) {
  const [run, setRun] = useState(null);

  const refresh = () => api.get("/api/validation/latest").then((v) => setRun(v?.id ? v : null)).catch(() => {});
  useEffect(() => { refresh(); }, [kick]);
  useEffect(() => {
    if (!run?.id) return;
    const id = setInterval(refresh, run.status === "running" ? 700 : 8000);
    return () => clearInterval(id);
  }, [run?.id, run?.status]);

  if (!run) return null;
  const host = agents[run.agent_id]?.hostname || "endpoint";
  const steps = run.steps || FALLBACK.map((label) => ({ label, state: "todo" }));
  const passed = run.status === "passed";
  const failed = run.status === "failed";
  const stateStyle = (state) => state === "done" ? "border-ok bg-ok text-bg" : state === "fail" ? "border-crit bg-crit text-white" : state === "active" ? "border-accent text-accent live-ring" : "border-line text-muted";

  return (
    <section className={`border-b px-6 py-4 ${passed ? "border-ok/30 bg-ok/5" : failed ? "border-crit/30 bg-crit/5" : "border-line bg-surface"}`} aria-label="Live protection proof">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <div className="font-cond text-[17px] font-semibold tracking-wide">LIVE PROTECTION PROOF</div>
        <span className="text-xs text-muted">Real drill on {host} · harmless simulation</span>
        <span className={`ml-auto text-sm font-semibold ${passed ? "text-ok" : failed ? "text-crit" : "text-accent"}`}>
          {passed ? `Caught in ${run.seconds.toFixed(2)} s` : failed ? "Protection check needs attention" : "Watching the response…"}
        </span>
      </div>
      <ol className="mt-3 grid gap-2 sm:grid-cols-4">
        {steps.map((step, i) => {
          const state = step.state || "todo";
          return (
            <li key={step.key || i} className="flex min-w-0 items-center gap-2">
              <span className={`grid h-6 w-6 shrink-0 place-items-center rounded-full border text-xs font-semibold ${stateStyle(state)}`}>
                {state === "done" ? "✓" : state === "fail" ? "!" : i + 1}
              </span>
              <div className="min-w-0">
                <div className="truncate text-xs font-medium">{step.label}</div>
                <div className="font-mono text-[10px] text-muted">
                  {state === "done" ? fmtTime(step.at).slice(0, 8) : state === "active" ? "in progress" : state === "fail" ? "not confirmed" : "waiting"}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
      {passed && run.steps?.[2]?.alert_id && (
        <button onClick={() => onOpenAlert(run.steps[2].alert_id)} className="mt-3 text-xs font-medium text-accent hover:underline">Open the real case →</button>
      )}
    </section>
  );
}
