import { CATEGORIES, catStyle, eventCategory, fmtTime } from "../lib/live.js";

export function CategoryLabel({ cat }) {
  const s = catStyle(cat);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: s.color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

export function CategoryFilter({ counts, active, onChange }) {
  const cats = Object.keys(CATEGORIES).filter((c) => counts[c]);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <div className="flex flex-wrap items-center gap-1">
      <FilterButton on={!active} onClick={() => onChange(null)} label="All" n={total} />
      {cats.map((c) => (
        <FilterButton key={c} on={active === c} onClick={() => onChange(active === c ? null : c)}
          label={catStyle(c).label} n={counts[c]} color={catStyle(c).color} />
      ))}
    </div>
  );
}

function FilterButton({ on, onClick, label, n, color }) {
  return (
    <button onClick={onClick} aria-pressed={on}
      className={`flex items-center gap-1.5 rounded-md px-2 py-1 text-xs transition-colors ${on ? "bg-raised text-text" : "text-muted hover:bg-surface hover:text-text-2"}`}>
      {color && <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />}
      {label} <span className="tabular-nums text-muted">{n}</span>
    </button>
  );
}

/** Splunk-style volume timeline: last 30 minutes of the events in view, 30-second buckets. */
export function VolumeTimeline({ events }) {
  const BUCKETS = 60, SPAN = 30 * 60 * 1000;
  const now = Date.now();
  const bins = Array(BUCKETS).fill(0);
  for (const e of events) {
    const age = now - Date.parse(e.ts);
    if (age >= 0 && age < SPAN) bins[BUCKETS - 1 - Math.floor(age / (SPAN / BUCKETS))]++;
  }
  const max = Math.max(1, ...bins);
  const total = bins.reduce((x, y) => x + y, 0);
  return (
    <div className="border-b border-line px-5 pb-3 pt-3">
      <div className="mb-2 flex items-baseline gap-2 text-xs">
        <span className="font-medium text-text-2">{total.toLocaleString()} events in the last 30 minutes</span>
        <span className="ml-auto text-muted">busiest 30s: {max}</span>
      </div>
      <div className="flex h-12 items-end gap-[2px]" role="img" aria-label={`Event volume over the last 30 minutes, ${total} events`}>
        {bins.map((v, i) => (
          <span key={i} title={`${v} events`} className="flex-1 rounded-[1px] bg-accent transition-[height] duration-300"
            style={{ height: v ? `${Math.max(6, (v / max) * 100)}%` : "2px", opacity: v ? 0.75 : 0.15 }} />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-muted"><span>30 min ago</span><span>15 min ago</span><span>now</span></div>
    </div>
  );
}

export default function EventFeed({ events, selectedId, onSelect }) {
  if (!events.length) {
    return (
      <div className="grid flex-1 place-items-center text-center">
        <div>
          <p className="font-medium">No matching events</p>
          <p className="mt-1 text-xs text-muted">Events stream in here as the agent ships them. Try clearing the search or filter.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="flex-1 overflow-auto">
      <table className="w-full table-fixed text-[13px]">
        <thead className="sticky top-0 z-10 bg-bg text-left text-xs text-muted">
          <tr className="border-b border-line">
            <th className="w-[120px] px-5 py-2 font-normal">Time</th>
            <th className="w-[110px] px-2 py-2 font-normal">Host</th>
            <th className="w-[120px] px-2 py-2 font-normal">Type</th>
            <th className="w-[56px] px-2 py-2 text-right font-normal">ID</th>
            <th className="px-4 py-2 font-normal">Summary</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} onClick={() => onSelect(e)}
              className={`cursor-pointer border-b border-line-soft transition-colors ${e._new ? "row-new" : ""} ${selectedId === e.id ? "bg-raised" : "hover:bg-surface"}`}>
              <td className="px-5 py-1.5 font-mono text-xs text-muted">{fmtTime(e.ts)}</td>
              <td className="truncate px-2 py-1.5 text-text-2">{e.hostname}</td>
              <td className="px-2 py-1.5"><CategoryLabel cat={eventCategory(e)} /></td>
              <td className="px-2 py-1.5 text-right font-mono text-xs text-muted">{e.event_id}</td>
              <td className="truncate px-4 py-1.5 font-mono text-xs" title={e.summary}>{e.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
