import { decodeEncoded, fmtTime, sevStyle } from "../lib/live.js";

const ACT = {
  network:  { color: "var(--c-network)", verb: "Network" },
  dns:      { color: "var(--c-dns)", verb: "DNS" },
  file:     { color: "var(--c-file)", verb: "File" },
  registry: { color: "var(--c-registry)", verb: "Registry" },
  access:   { color: "var(--color-crit)", verb: "Access" },
  inject:   { color: "var(--color-crit)", verb: "Injection" },
};

const countTree = (n) => {
  let procs = 0, acts = 0;
  const walk = (x) => { procs++; acts += x.activity.length + (x.more_activity || 0); x.children.forEach(walk); };
  walk(n);
  return { procs, acts };
};

/** Falcon-style process lineage: ancestors → the flagged process → everything it spawned and touched. */
export default function ProcessTree({ tree, alert, terminated }) {
  const sev = sevStyle(alert.severity);
  const contained = !!terminated;
  const { procs, acts } = countTree(tree.root);
  return (
    <div>
      <p className="mb-4 text-xs text-muted">
        {procs} process{procs === 1 ? "" : "es"}, {acts} action{acts === 1 ? "" : "s"}. Source: Sysmon
      </p>
      <ul>
        <Node node={tree.root} sev={sev} contained={contained} underFocus={false} isRoot last />
      </ul>
    </div>
  );
}

// geometry: the 20px glyph sits 14px (plain row) or 23px (boxed focus row) from the row's left edge
const GLYPH_X = (focus) => (focus ? 23 : 14);
const GLYPH_Y = (focus) => (focus ? 21 : 14);

function Node({ node, sev, contained, underFocus, isRoot, last }) {
  const focus = !!node.focus;
  const killed = contained && (focus || underFocus);
  const decoded = decodeEncoded(node.cmd);
  const elevated = /high|system/i.test(node.integrity || "");
  const tone = killed ? "var(--color-ok)" : focus ? sev.color : "var(--color-muted)";

  return (
    <li className="relative">
      {/* elbow connectors drawn from the parent's spine */}
      {!isRoot && <span className="absolute -left-5 top-0 w-px bg-line" style={{ height: GLYPH_Y(focus) }} />}
      {!isRoot && !last && <span className="absolute -left-5 bottom-0 w-px bg-line" style={{ top: GLYPH_Y(focus) }} />}
      {!isRoot && <span className="absolute -left-5 h-px bg-line" style={{ top: GLYPH_Y(focus), width: 20 + GLYPH_X(focus) - 10 }} />}

      <div className={`relative mb-2 rounded-lg ${focus ? "border bg-surface px-3 py-2.5" : "px-1 py-1"}`}
        style={focus ? { borderColor: killed ? "color-mix(in srgb, var(--color-ok) 45%, transparent)" : `color-mix(in srgb, ${sev.color} 55%, transparent)`,
          boxShadow: killed ? "none" : `0 0 0 3px color-mix(in srgb, ${sev.color} 12%, transparent)` } : undefined}>
        {node.children.length > 0 && (
          <span className="absolute w-px bg-line" style={{ left: focus ? 22 : 14, top: focus ? 30 : 24, bottom: focus ? -9 : -8 }} />
        )}
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="grid h-5 w-5 shrink-0 place-items-center rounded border" style={{ borderColor: tone, color: tone }}>
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M7 9l3 3-3 3M13 15h4" />
            </svg>
          </span>
          <span className={`font-semibold ${killed ? "text-text-2 line-through decoration-ok/70" : node.stub ? "text-text-2" : ""}`}>{node.name}</span>
          {node.pid && <span className="font-mono text-xs text-muted">PID {node.pid}</span>}
          {elevated && <span className="rounded border border-warn/40 px-1 text-[11px] text-warn" title={`Integrity level: ${node.integrity}`}>elevated</span>}
          {node.user && <span className="font-mono text-xs text-muted">{node.user}</span>}
          {focus && !killed && <span className="text-xs font-medium" style={{ color: sev.color }}>flagged by this alert</span>}
          {node.stub && <span className="text-xs text-muted">started before logging began</span>}
          {node.exited && !killed && <span className="text-xs text-muted">exited</span>}
          {node.ts && <span className="ml-auto font-mono text-xs text-muted">{fmtTime(node.ts)}</span>}
          {killed && focus && (
            <span className={`stamp rounded border-2 border-ok px-1.5 py-0.5 font-mono text-[11px] font-medium text-ok ${node.ts ? "ml-3" : "ml-auto"}`}>
              Terminated
            </span>
          )}
        </div>
        {node.cmd && (
          <p className={`mt-1 break-all pl-7 font-mono text-xs leading-relaxed ${focus ? "text-text-2" : "text-muted"} line-clamp-2`} title={node.cmd}>{node.cmd}</p>
        )}
        {decoded && (
          <div className="ml-7 mt-2 rounded-md border border-line-soft bg-bg px-2.5 py-2">
            <div className="text-[11px] text-muted">Decoded payload</div>
            <code className="mt-0.5 block break-all font-mono text-[13px] text-text">{decoded}</code>
          </div>
        )}
        {node.activity.length > 0 && (
          <ul className="ml-7 mt-1.5 space-y-0.5">
            {node.activity.map((a) => (
              <li key={a.id} className="flex items-baseline gap-2 text-xs">
                <span className="w-16 shrink-0" style={{ color: ACT[a.kind]?.color }}>{ACT[a.kind]?.verb || a.kind}</span>
                <span className="min-w-0 truncate font-mono text-text-2" title={a.summary}>{a.summary.replace(/^\S+\.exe\s+/i, "")}</span>
              </li>
            ))}
            {node.more_activity > 0 && <li className="text-xs text-muted">and {node.more_activity} more</li>}
          </ul>
        )}
      </div>

      {node.children.length > 0 && (
        <ul className="pl-5" style={{ marginLeft: GLYPH_X(focus) }}>
          {node.children.map((c, i) => (
            <Node key={c.guid || i} node={c} sev={sev} contained={contained} underFocus={underFocus || focus}
              last={i === node.children.length - 1 && !node.more_children} />
          ))}
          {node.more_children && <li className="relative text-xs text-muted"><span className="absolute -left-5 top-0 h-2 w-px bg-line" />More child processes not shown</li>}
        </ul>
      )}
    </li>
  );
}
