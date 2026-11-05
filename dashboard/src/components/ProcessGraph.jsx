import { useEffect, useMemo, useRef, useState } from "react";
import { decodeEncoded, fmtTime, sevStyle } from "../lib/live.js";
import ProcessTree from "./ProcessTree.jsx";

export const KIND = {
  network:  { color: "var(--c-network)", label: "Network" },
  dns:      { color: "var(--c-dns)", label: "DNS" },
  file:     { color: "var(--c-file)", label: "File" },
  registry: { color: "var(--c-registry)", label: "Registry" },
  access:   { color: "var(--color-crit)", label: "Memory access" },
  inject:   { color: "var(--color-crit)", label: "Injection" },
};

const lastSeg = (s) => s.split(/[\\/]/).filter(Boolean).pop() || s;

/** Short, scannable label for what a process touched; full text stays in the tooltip. */
export function target(a) {
  const t = a.summary.replace(/^\S+\.exe\s+/i, "");
  if (a.kind === "network") return (t.match(/(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)/) || t.match(/([\w.-]+:\d+)/) || [t])[0].replace(/^-> /, "");
  if (a.kind === "dns") return t.replace(/^resolved\s+/i, "").split(/\s/)[0];
  if (a.kind === "access" || a.kind === "inject") return (t.match(/(\S+\.exe)/gi) || [t]).pop();
  return lastSeg(t.replace(/^(created|set|deleted|renamed)\s+/i, "").replace(/\s*=.*$/, ""));
}

function satellites(node) {
  const m = new Map();
  for (const a of node.activity) {
    const label = target(a);
    const k = `${a.kind}|${label}`;
    const cur = m.get(k);
    if (cur) { cur.count++; cur.items.push(a); }
    else m.set(k, { kind: a.kind, label, full: a.summary, count: 1, ts: a.ts, items: [a] });
  }
  const list = [...m.values()];
  const extra = Math.max(0, list.length - 4) + (node.more_activity || 0);
  return { list: list.slice(0, 4), extra };
}

function useWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

// glyph centre inside a node box: 1px border + 12px padding + 10px half-glyph, 1px + 8px + 10px down
const GX = 23, GY = 19;
const NODE_H = 58, DECODED_H = 46, SAT_H = 26, SAT_GAP = 6, ROW_GAP = 22, INDENT = 44;

/**
 * Process lineage drawn as a graph: processes down the left, everything each one
 * touched branching off to the right. Click any node to inspect it; replay walks
 * the attack forward one step at a time.
 */
export default function ProcessGraph({ tree, alert, terminated, killCmd, selectedKey, onSelect }) {
  const [ref, W] = useWidth();
  const sev = sevStyle(alert.severity);

  // flatten the tree, remembering who is under the flagged process
  const rows = [];
  const walk = (n, depth, parentIdx, underFocus) => {
    const idx = rows.length;
    rows.push({ n, depth, parentIdx, underFocus, decoded: decodeEncoded(n.cmd), sats: satellites(n) });
    n.children.forEach((c) => walk(c, depth + 1, idx, underFocus || n.focus));
  };
  walk(tree.root, 0, -1, false);

  // replay script: every process start, every action, the detection and the kill, in time order
  const steps = useMemo(() => {
    const s = [];
    rows.forEach((r, i) => {
      s.push({ key: `n${i}`, ts: r.n.ts, label: r.n.stub ? `${r.n.name} was already running` : `${r.n.name} started` });
      r.sats.list.forEach((x, j) => s.push({ key: `s${i}-${j}`, ts: x.ts, label: `${r.n.name}: ${KIND[x.kind]?.label || x.kind} ${x.label}` }));
    });
    s.push({ key: "alert", ts: alert.ts, label: `${alert.rule_id} fired: ${alert.rule_title}`, tone: sev.color });
    if (killCmd?.status === "done") s.push({ key: "kill", ts: killCmd.completed_at, label: "Aegis terminated the process", tone: "var(--color-ok)" });
    return s.map((x, k) => ({ ...x, order: k })).sort((a, b) => (a.ts || "").localeCompare(b.ts || "") || a.order - b.order);
  }, [tree, alert.id, alert.ts, killCmd?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const last = steps.length - 1;
  const [step, setStep] = useState(last);
  const [playing, setPlaying] = useState(false);
  useEffect(() => { setStep(last); setPlaying(false); }, [alert.id, last]);
  useEffect(() => {
    if (!playing) return;
    if (step >= last) { setPlaying(false); return; }
    const id = setTimeout(() => setStep((n) => n + 1), 750);
    return () => clearTimeout(id);
  }, [playing, step, last]);

  const at = Object.fromEntries(steps.map((s, i) => [s.key, i]));
  const seen = (key) => (at[key] ?? 0) <= step;
  const current = steps[step]?.key;
  const detected = seen("alert");
  const killedNow = terminated && (at.kill === undefined || seen("kill"));

  const narrow = W > 0 && W < 560;
  const procW = Math.min(440, Math.round(W * 0.46));
  const satX = procW + Math.max(64, Math.min(140, Math.round(W * 0.09)));
  const satW = Math.max(120, W - satX);

  let y = 0;
  for (const r of rows) {
    const nodeH = NODE_H + (r.decoded ? DECODED_H : 0);
    const nSat = r.sats.list.length + (r.sats.extra ? 1 : 0);
    const satsH = nSat ? nSat * SAT_H + (nSat - 1) * SAT_GAP : 0;
    r.h = Math.max(nodeH, satsH);
    r.nodeH = nodeH;
    r.y = y;
    r.x = r.depth * INDENT;
    r.w = procW - r.x;
    r.satY0 = y + (r.h - satsH) / 2;
    r.killed = killedNow && (r.n.focus || r.underFocus);
    y += r.h + ROW_GAP;
  }
  const H = y - ROW_GAP;
  const procs = rows.length;
  const acts = rows.reduce((s, r) => s + r.n.activity.length + (r.n.more_activity || 0), 0);
  const replaying = step < last || playing;
  // filter (not opacity) so it composes with the node-in entrance animation, which owns opacity
  const fade = (key, dim = 1) => ({ filter: `opacity(${seen(key) ? dim : 0.08})`, transition: "filter .35s ease" });
  const ring = (key) => (replaying && current === key ? "0 0 0 2px var(--color-accent)" : null);

  return (
    <div ref={ref}>
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-muted">
        <span>{procs} process{procs === 1 ? "" : "es"}, {acts} action{acts === 1 ? "" : "s"}. Source: Sysmon</span>
        <span className="ml-auto flex items-center gap-4">
          <span className="flex items-center gap-1.5"><svg width="18" height="2" aria-hidden="true"><line x1="0" y1="1" x2="18" y2="1" stroke="var(--color-text-2)" /></svg>Observed</span>
          <span className="flex items-center gap-1.5"><svg width="18" height="2" aria-hidden="true"><line x1="0" y1="1" x2="18" y2="1" stroke="var(--color-text-2)" strokeDasharray="3 3" /></svg>Inferred</span>
        </span>
      </div>

      {W === 0 ? null : narrow ? <ProcessTree tree={tree} alert={alert} terminated={terminated} /> : (
        <div className="relative" style={{ height: H }} key={alert.id}>
          <svg width={W} height={H} className="absolute inset-0 overflow-visible" aria-hidden="true">
            {rows.map((r, i) => {
              const out = [];
              if (r.parentIdx >= 0) {
                const p = rows[r.parentIdx];
                const sx = p.x + GX, sy = p.y + p.nodeH, ty = r.y + GY;
                const inferred = p.n.stub; // we never saw the parent start; lineage comes from the child's fields
                out.push(
                  <g key={`p${i}`} style={fade(`n${i}`)}>
                    <path d={`M${sx} ${sy} V${ty - 8} Q${sx} ${ty} ${sx + 8} ${ty} H${r.x}`} pathLength="1"
                      fill="none" stroke={r.killed ? "var(--color-ok)" : r.n.focus && detected ? sev.color : "var(--color-muted)"}
                      strokeOpacity={r.n.focus || r.killed ? 1 : 0.6} strokeWidth={r.n.focus ? 1.5 : 1}
                      strokeDasharray={inferred ? "0.025 0.02" : undefined} className={inferred ? "" : "edge-draw"} style={{ animationDelay: `${i * 90}ms` }} />
                  </g>,
                );
              }
              const ox = r.x + r.w, oy = r.y + GY;
              const all = [...r.sats.list, ...(r.sats.extra ? [{ more: true }] : [])];
              all.forEach((s, j) => {
                const ty = r.satY0 + j * (SAT_H + SAT_GAP) + SAT_H / 2;
                const c = s.more ? "var(--color-line)" : KIND[s.kind]?.color || "var(--color-muted)";
                out.push(
                  <g key={`s${i}-${j}`} style={fade(s.more ? `n${i}` : `s${i}-${j}`)}>
                    <path d={`M${ox} ${oy} C${ox + 36} ${oy} ${satX - 36} ${ty} ${satX} ${ty}`} pathLength="1"
                      fill="none" stroke={r.killed ? "var(--color-muted)" : c} strokeOpacity={r.killed ? 0.5 : 0.6} strokeWidth="1.25"
                      strokeDasharray={r.killed ? "0.012 0.012" : undefined}
                      className={r.killed ? "" : "edge-draw"} style={{ animationDelay: `${i * 90 + 180 + j * 40}ms` }} />
                  </g>,
                );
              });
              return out;
            })}
          </svg>

          {rows.map((r, i) => {
            const focus = !!r.n.focus;
            const hot = focus && detected;
            const tone = r.killed ? "var(--color-ok)" : hot ? sev.color : "var(--color-line)";
            const elevated = /high|system/i.test(r.n.integrity || "");
            const key = `n${i}`;
            const sel = selectedKey === key;
            return (
              <div key={key}>
                <button type="button" onClick={() => onSelect?.({ key, type: "process", node: r.n, decoded: r.decoded })}
                  className="node-in absolute rounded-lg border bg-surface px-3 py-2 text-left transition-colors hover:bg-raised"
                  style={{
                    left: r.x, top: r.y, width: r.w, height: r.nodeH, animationDelay: `${i * 90}ms`,
                    borderColor: sel ? "var(--color-accent)" : tone,
                    borderStyle: r.n.stub ? "dashed" : "solid",
                    boxShadow: ring(key) || (hot && !r.killed ? `0 0 0 3px color-mix(in srgb, ${sev.color} 14%, transparent), 0 8px 30px -10px ${sev.color}` : "none"),
                    ...fade(key),
                  }}>
                  <div className="flex items-center gap-2">
                    <span className="grid h-5 w-5 shrink-0 place-items-center rounded" style={{ background: `color-mix(in srgb, ${hot || r.killed ? tone : "var(--color-muted)"} 18%, transparent)`, color: hot || r.killed ? tone : "var(--color-text-2)" }}>
                      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden="true"><path d="M7 9l3 3-3 3M13 15h4" /></svg>
                    </span>
                    <span className={`truncate font-semibold ${r.killed ? "text-text-2 line-through decoration-ok/70" : ""}`} title={r.n.image}>{r.n.name}</span>
                    {r.n.pid && <span className="shrink-0 font-mono text-[11px] text-muted">{r.n.pid}</span>}
                    {elevated && <span className="shrink-0 rounded-sm bg-warn/15 px-1 text-[10px] font-medium text-warn" title={`Integrity: ${r.n.integrity}`}>admin</span>}
                    <span className="ml-auto shrink-0">
                      {r.killed && focus ? <span className="stamp inline-block rounded border-2 border-ok px-1 font-mono text-[10px] font-medium text-ok">Terminated</span>
                        : r.n.stub ? <span className="text-[11px] text-muted">pre-existing</span>
                        : r.n.exited ? <span className="text-[11px] text-muted">exited</span>
                        : r.n.ts && <span className="font-mono text-[11px] text-muted">{fmtTime(r.n.ts).slice(0, 8)}</span>}
                    </span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[11px] text-muted" title={r.n.cmd}>{r.n.cmd || r.n.image}</p>
                  {r.decoded && (
                    <div className="mt-2 flex items-baseline gap-2 rounded border border-line-soft bg-bg px-2 py-1.5">
                      <span className="shrink-0 text-[10px] text-muted">decoded</span>
                      <code className="truncate font-mono text-[13px] text-text" title={r.decoded}>{r.decoded}</code>
                    </div>
                  )}
                </button>

                {[...r.sats.list, ...(r.sats.extra ? [{ more: true, count: r.sats.extra }] : [])].map((s, j) => {
                  const skey = `s${i}-${j}`;
                  const ssel = selectedKey === skey;
                  return (
                    <button type="button" key={j} disabled={s.more}
                      onClick={() => !s.more && onSelect?.({ key: skey, type: "activity", node: r.n, group: s })}
                      className="node-in absolute flex items-center gap-2 rounded-md border bg-bg px-2 text-left text-xs transition-colors enabled:hover:bg-raised"
                      title={s.full}
                      style={{
                        left: satX, top: r.satY0 + j * (SAT_H + SAT_GAP), height: SAT_H, maxWidth: satW,
                        borderColor: ssel ? "var(--color-accent)" : r.killed ? "var(--color-line-soft)" : "var(--color-line)",
                        boxShadow: ring(skey) || "none",
                        animationDelay: `${i * 90 + 260 + j * 40}ms`,
                        ...(s.more ? fade(`n${i}`) : fade(skey, r.killed ? 0.55 : 1)),
                      }}>
                      {s.more ? <span className="text-muted">{s.count} more</span> : (
                        <>
                          <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: KIND[s.kind]?.color }} />
                          <span className="shrink-0 text-muted">{KIND[s.kind]?.label || s.kind}</span>
                          <span className="truncate font-mono text-text-2">{s.label}</span>
                          {s.count > 1 && <span className="shrink-0 tabular-nums text-muted">×{s.count}</span>}
                        </>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}

      {!narrow && W > 0 && steps.length > 1 && (
        <Replay steps={steps} step={step} playing={playing}
          onPlay={() => { if (step >= last) setStep(0); setPlaying((p) => !p); }}
          onSeek={(n) => { setPlaying(false); setStep(n); }} />
      )}
    </div>
  );
}

/** Play / scrub through the attack in the order it happened. */
function Replay({ steps, step, playing, onPlay, onSeek }) {
  const last = steps.length - 1;
  const cur = steps[step];
  const pct = (i) => (last ? (i / last) * 100 : 0);
  return (
    <div className="mt-5 flex items-center gap-4 rounded-lg bg-surface px-4 py-3">
      <button onClick={onPlay} aria-label={playing ? "Pause replay" : "Replay the attack"}
        className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-accent text-bg transition hover:brightness-110">
        {playing
          ? <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="1.5" width="3" height="9" rx="1" fill="currentColor" /><rect x="7" y="1.5" width="3" height="9" rx="1" fill="currentColor" /></svg>
          : <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 1.5v9l7.5-4.5z" fill="currentColor" /></svg>}
      </button>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-3 text-xs">
          <span className="font-medium text-text">Replay</span>
          <span className="min-w-0 truncate" style={{ color: cur?.tone || "var(--color-text-2)" }}>{cur?.label}</span>
          <span className="ml-auto shrink-0 font-mono text-muted">{cur?.ts ? fmtTime(cur.ts).slice(0, 8) : "before logging"}</span>
          <span className="shrink-0 tabular-nums text-muted">{step + 1}/{steps.length}</span>
        </div>
        <div className="relative mt-2 h-4">
          <div className="absolute inset-x-0 top-[7px] h-[2px] rounded-full bg-line" />
          <div className="absolute left-0 top-[7px] h-[2px] rounded-full bg-accent transition-[width] duration-300" style={{ width: `${pct(step)}%` }} />
          {steps.map((s, i) => (
            <button key={s.key} onClick={() => onSeek(i)} title={s.label} aria-label={`Step ${i + 1}: ${s.label}`}
              className="absolute top-[3px] h-[10px] w-[10px] -translate-x-1/2 rounded-full border-2 transition-colors"
              style={{ left: `${pct(i)}%`, borderColor: s.tone || (i <= step ? "var(--color-accent)" : "var(--color-line)"),
                background: i <= step ? (s.tone || "var(--color-accent)") : "var(--color-bg)" }} />
          ))}
        </div>
      </div>
    </div>
  );
}
