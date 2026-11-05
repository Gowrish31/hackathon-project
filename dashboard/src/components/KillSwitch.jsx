import { useEffect, useRef, useState } from "react";
import { basename, fmtTime } from "../lib/live.js";

const ms = (a, b) => (a && b ? Date.parse(b) - Date.parse(a) : null);

/** Counts from 0 up to `to` over `dur` ms (replaying the attack's real pace), then holds. */
function useCountUp(to, dur, key) {
  const [n, setN] = useState(0);
  const raf = useRef();
  useEffect(() => {
    if (!Number.isFinite(to)) return;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce || to <= 0) { setN(to); return; }
    const t0 = performance.now();
    const step = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      setN(Math.round(to * p));
      if (p < 1) raf.current = requestAnimationFrame(step);
    };
    setN(0);
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [to, dur, key]);
  return n;
}

/** Ransomware canary case: what tripped, how fast the agent killed it, and how much it got to. */
export default function KillSwitch({ alert }) {
  const c = alert.context || {};
  const killed = c.Action === "killed";
  const hit = Number(c.FilesAffected || 0);
  const scanned = Number(c.FilesScanned || 0);
  const runMs = ms(c.ProcessStartedAt, c.KilledAt || c.TrippedAt);
  // replay at the attack's own pace, clamped so the room can follow it
  const n = useCountUp(hit, Math.min(4000, Math.max(1200, runMs || 2000)), alert.id);
  const done = n === hit;
  const saved = scanned > hit ? scanned - hit : null;
  let suspects = [];
  try { suspects = JSON.parse(c.Suspects || "[]"); } catch { /* old agent */ }

  const tone = killed ? "var(--color-ok)" : "var(--color-crit)";
  const steps = [
    { label: "Process started", at: c.ProcessStartedAt, detail: basename(c.Image || "") || "unknown" },
    { label: "Canary tripped", at: c.TrippedAt, detail: `${basename(c.CanaryFile || "")} ${c.Change || ""}`.trim() },
    killed
      ? { label: "Killed on endpoint", at: c.KilledAt, detail: `${c.KillMs} ms after the trip, no console round-trip` }
      : { label: "Not killed", at: null, detail: c.Action },
  ];

  return (
    <div className="rounded-lg border border-line bg-surface">
      <div className="grid gap-px overflow-hidden rounded-t-lg bg-line sm:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div className="bg-surface px-5 py-4">
          <div className="text-xs text-muted">Files encrypted before the kill-switch</div>
          <div className="mt-1 flex items-baseline gap-3">
            <span className="font-cond text-[64px] font-semibold leading-none tabular-nums" style={{ color: done ? tone : "var(--color-crit)" }}
              aria-live="polite" aria-label={`${hit} files encrypted`}>{n}</span>
            {scanned > 0 && <span className="text-sm text-muted">of {scanned} in {c.Drill === "true" ? "the drill folder" : basename(c.ScanRoot || "")}</span>}
          </div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-raised" aria-hidden="true">
            <div className="h-full rounded-full" style={{ width: `${scanned ? (n / scanned) * 100 : 0}%`, background: "var(--color-crit)", transition: "width 60ms linear" }} />
          </div>
          <p className="mt-2 text-xs text-text-2" style={{ visibility: done ? "visible" : "hidden" }}>
            {killed
              ? <><span className="text-ok">Stopped.</span> {saved != null ? `${saved} files never reached.` : ""} Ran for {(runMs / 1000).toFixed(1)} s before it was killed.</>
              : <><span className="text-crit">Not stopped automatically.</span> Kill or isolate the host now.</>}
          </p>
        </div>
        <div className="flex flex-col justify-center bg-surface px-5 py-4">
          <div className="text-xs text-muted">Trip to kill</div>
          <div className="font-cond text-[40px] font-semibold leading-none tabular-nums" style={{ color: tone }}>
            {killed ? <>{c.KillMs}<span className="ml-1 text-lg text-muted">ms</span></> : "—"}
          </div>
          <div className="mt-2 text-xs text-text-2">
            Decided on the endpoint by write volume
            {c.BytesWritten && <> ({(Number(c.BytesWritten) / 1e6).toFixed(1)} MB in the last second)</>}
            , confidence <span className="font-mono">{c.Confidence || "?"}</span>.
          </div>
        </div>
      </div>

      <ol className="grid gap-3 px-5 py-4 sm:grid-cols-3">
        {steps.map((s, i) => (
          <li key={i} className="min-w-0">
            <div className="flex items-center gap-2 text-xs">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: i === 2 ? tone : "var(--color-crit)" }} />
              <span className="font-medium text-text">{s.label}</span>
              {s.at && <span className="ml-auto font-mono text-[11px] text-muted">{fmtTime(s.at)}</span>}
            </div>
            <p className="mt-1 truncate pl-4 font-mono text-[11px] text-text-2" title={s.detail}>{s.detail}</p>
          </li>
        ))}
      </ol>

      {suspects.length > 1 && (
        <div className="border-t border-line px-5 py-3 text-xs text-muted">
          Other writers at the time:{" "}
          {suspects.slice(1).map((s) => <span key={s.pid} className="mr-3 font-mono text-text-2">{s.image} {(s.write / 1e3).toFixed(0)} KB</span>)}
        </div>
      )}
    </div>
  );
}
