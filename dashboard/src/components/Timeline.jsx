import { useEffect, useRef, useState } from "react";
import { SEVERITY, sevStyle, fmtTime } from "../lib/live.js";

const RANGES = [["1h", 60], ["3h", 180], ["12h", 720], ["24h", 1440]];

function useWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(800);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

export function SevGlyph({ sev, x, y, r = 6, hollow = false, className = "" }) {
  const c = sevStyle(sev).color;
  const p = { fill: hollow ? "var(--color-bg)" : c, stroke: c, strokeWidth: 1.5, className };
  if (sev === "critical") return <path d={`M${x} ${y - r - 1}L${x + r + 1} ${y}L${x} ${y + r + 1}L${x - r - 1} ${y}Z`} {...p} />;
  if (sev === "high") return <path d={`M${x} ${y - r}L${x + r} ${y + r * 0.8}L${x - r} ${y + r * 0.8}Z`} {...p} />;
  return <circle cx={x} cy={y} r={r - 1} {...p} />;
}

/**
 * The page's opening read: a live strip of the last hours on this fleet.
 * Telemetry volume as a floor, every detection as a marker where it happened,
 * incidents as the spans that tie them together.
 */
export default function ThreatTimeline({ alerts, incidents, events, response, agentsOnline, agentsTotal, onOpen, onSeverity }) {
  const [range, setRange] = useState("3h");
  const [hover, setHover] = useState(null);
  const [ref, width] = useWidth();
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 10000);
    return () => clearInterval(id);
  }, []);

  const minutes = RANGES.find(([k]) => k === range)[1];
  const now = Date.now();
  const start = now - minutes * 60000;
  const H = 76, laneY = 26, floor = H - 18, PAD = 10;
  const W = Math.max(200, width);
  const x = (t) => PAD + ((Date.parse(t) - start) / (now - start)) * (W - PAD * 2);
  const inRange = (t) => Date.parse(t) >= start;

  const BINS = 90;
  const bins = Array(BINS).fill(0);
  for (const e of events) {
    const i = Math.floor(((Date.parse(e.ts) - start) / (now - start)) * BINS);
    if (i >= 0 && i < BINS) bins[i]++;
  }
  const bmax = Math.max(1, ...bins);
  const bw = (W - PAD * 2) / BINS;

  const ticks = [];
  const step = minutes <= 60 ? 10 : minutes <= 180 ? 30 : minutes <= 720 ? 120 : 240;
  const first = Math.ceil(start / (step * 60000)) * step * 60000;
  for (let t = first; t < now; t += step * 60000) {
    const px = PAD + ((t - start) / (now - start)) * (W - PAD * 2);
    if (px < W - 150) ticks.push(t);
  }

  const active = alerts.filter((a) => a.status === "open" || a.status === "acknowledged");
  const shown = alerts.filter((a) => inRange(a.ts));

  return (
    <section className="grid shrink-0 grid-cols-[auto_minmax(0,1fr)] border-b border-line" aria-label="Threat timeline">
      {/* summary */}
      <div className="flex min-w-[220px] flex-col justify-center gap-1.5 border-r border-line px-5 py-3">
        <div className="flex items-baseline gap-2">
          <span className={`font-cond text-[34px] font-semibold leading-none tabular-nums ${active.length ? "" : "text-text-2"}`}>{active.length}</span>
          <span className="text-text-2">{active.length === 1 ? "alert open" : "alerts open"}</span>
        </div>
        <div className="flex gap-3 text-xs">
          {Object.keys(SEVERITY).map((k) => {
            const n = active.filter((a) => a.severity === k).length;
            return (
              <button key={k} onClick={() => onSeverity(k)} disabled={!n} title={`${SEVERITY[k].label}: ${n}`}
                className={`flex items-center gap-1 ${n ? "text-text-2 hover:text-text" : "text-muted/60"}`}>
                <svg width="10" height="10" viewBox="-6 -6 12 12" aria-hidden="true"><SevGlyph sev={k} x={0} y={0} r={4} hollow={!n} /></svg>
                <span className="tabular-nums">{n}</span>
              </button>
            );
          })}
        </div>
        <div className="text-xs text-muted">
          <span className={response?.stopped ? "text-ok" : ""}>
            {response?.stopped ?? 0} stopped{response?.avg_s != null && <>, avg <span className="tabular-nums">{response.avg_s.toFixed(2)} s</span></>}
          </span>
          <span className="mx-2 text-line">|</span>
          <span className="tabular-nums">{agentsOnline}/{agentsTotal}</span> endpoints live
        </div>
      </div>

      {/* strip */}
      <div className="relative min-w-0 px-3 pt-2">
        <div className="absolute bottom-0.5 right-4 z-10 flex gap-0.5 rounded-md bg-bg p-0.5 text-[11px]">
          {RANGES.map(([k]) => (
            <button key={k} onClick={() => setRange(k)} aria-pressed={range === k}
              className={`rounded px-1.5 py-0.5 ${range === k ? "bg-raised text-text" : "text-muted hover:text-text-2"}`}>{k}</button>
          ))}
        </div>
        <div ref={ref} className="relative">
          <svg width={W} height={H} className="block" role="img"
            aria-label={`${shown.length} detections in the last ${range}`}>
            {/* gridlines + time axis */}
            {ticks.map((t) => (
              <g key={t}>
                <line x1={x(new Date(t).toISOString())} x2={x(new Date(t).toISOString())} y1={6} y2={floor} stroke="var(--color-line-soft)" />
                <text x={x(new Date(t).toISOString())} y={H - 4} textAnchor="middle" className="fill-muted font-mono text-[10px]">
                  {new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })}
                </text>
              </g>
            ))}
            {/* telemetry floor */}
            {bins.map((v, i) => v > 0 && (
              <rect key={i} x={PAD + i * bw} y={floor - (v / bmax) * 18} width={Math.max(1, bw - 1)} height={(v / bmax) * 18}
                fill="var(--color-accent)" opacity="0.5" />
            ))}
            <line x1={PAD} x2={W - PAD} y1={floor} y2={floor} stroke="var(--color-line)" />

            {/* incident spans */}
            {incidents.filter((inc) => inRange(inc.last_ts)).map((inc) => {
              const done = inc.status === "contained" || inc.status === "closed";
              const c = done ? (inc.status === "contained" ? "var(--color-ok)" : "var(--color-muted)") : sevStyle(inc.severity).color;
              const x1 = Math.max(PAD, x(inc.first_ts)), x2 = x(inc.last_ts);
              return x2 - x1 > 2 && (
                <line key={inc.id} x1={x1} x2={x2} y1={laneY} y2={laneY} stroke={c} strokeWidth="3" strokeLinecap="round" opacity={done ? 0.35 : 0.5} />
              );
            })}

            {/* now */}
            <line x1={W - PAD} x2={W - PAD} y1={6} y2={floor} stroke="var(--color-accent)" strokeDasharray="2 3" opacity="0.6" />
            <circle cx={W - PAD} cy={floor} r="3" fill="var(--color-accent)" className="live-ring" style={{ color: "var(--color-accent)" }} />

            {/* detections */}
            {shown.slice().sort((a, b) => SEVERITY[a.severity].rank - SEVERITY[b.severity].rank).map((a) => {
              const done = a.status === "contained" || a.status === "closed";
              const cx = x(a.ts);
              return (
                <g key={a.id} className="cursor-pointer" onClick={() => onOpen(a)}
                  onMouseEnter={() => setHover({ a, cx })} onMouseLeave={() => setHover(null)}>
                  <rect x={cx - 9} y={laneY - 12} width="18" height="24" fill="transparent" />
                  {a.status === "contained"
                    ? <g><circle cx={cx} cy={laneY} r="6" fill="var(--color-bg)" stroke="var(--color-ok)" strokeWidth="1.5" />
                        <path d={`M${cx - 2.5} ${laneY}l1.8 1.8 3.2-3.6`} fill="none" stroke="var(--color-ok)" strokeWidth="1.5" /></g>
                    : <SevGlyph sev={a.severity} x={cx} y={laneY} hollow={done} className={a._new ? "marker-pop" : ""} />}
                </g>
              );
            })}
          </svg>
          {hover && (
            <div className="pointer-events-none absolute top-[44px] z-20 w-64 -translate-x-1/2 rounded-md border border-line bg-raised px-3 py-2 text-xs shadow-[0_8px_24px_var(--shadow)]"
              style={{ left: Math.min(Math.max(hover.cx, 130), W - 130) }}>
              <div className="font-medium text-text">{hover.a.rule_title}</div>
              <div className="mt-0.5 text-muted">{hover.a.hostname}, {fmtTime(hover.a.ts)}</div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
