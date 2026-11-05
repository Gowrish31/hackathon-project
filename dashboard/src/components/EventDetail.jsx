import { CategoryLabel } from "./EventFeed.jsx";
import { fmtTime } from "../lib/live.js";

export default function EventDetail({ event, onClose }) {
  if (!event) return null;
  const fields = Object.entries(event.data || {});
  return (
    <aside className="flex w-[440px] shrink-0 flex-col border-l border-line bg-surface" aria-label="Event details">
      <div className="flex items-center gap-3 border-b border-line px-5 py-3">
        <CategoryLabel cat={event.category} />
        <span className="font-mono text-xs text-muted">Event {event.event_id}</span>
        <button onClick={onClose} className="ml-auto grid h-7 w-7 place-items-center rounded-md text-muted hover:bg-raised hover:text-text" aria-label="Close event details">×</button>
      </div>
      <div className="flex-1 overflow-y-auto px-5 py-4">
        <p className="break-words font-mono text-[13px] leading-relaxed">{event.summary}</p>
        <dl className="mt-4 grid grid-cols-[90px_1fr] gap-y-1.5 text-xs">
          <dt className="text-muted">Time</dt><dd className="font-mono">{fmtTime(event.ts)}</dd>
          <dt className="text-muted">Host</dt><dd>{event.hostname}</dd>
          <dt className="text-muted">Channel</dt><dd className="break-all text-text-2">{event.channel}</dd>
        </dl>
        <h3 className="mb-2 mt-6 text-[13px] font-semibold">Fields</h3>
        <div className="overflow-hidden rounded-lg border border-line bg-bg">
          {fields.map(([k, v]) => (
            <div key={k} className="grid grid-cols-[140px_1fr] gap-3 border-b border-line-soft px-3 py-1.5 text-xs last:border-0">
              <span className="truncate text-muted" title={k}>{k}</span>
              <span className="break-all font-mono text-text-2">{v || <span className="text-muted">empty</span>}</span>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
