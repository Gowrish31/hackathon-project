import { useState } from "react";
import { SEVERITY } from "../lib/live.js";

const ICONS = {
  overview: (
    <>
      <rect x="3.5" y="3.5" width="7" height="9" rx="1.2" />
      <rect x="13.5" y="3.5" width="7" height="5" rx="1.2" />
      <rect x="13.5" y="11.5" width="7" height="9" rx="1.2" />
      <rect x="3.5" y="15.5" width="7" height="5" rx="1.2" />
    </>
  ),
  alerts: (
    <path d="M12 3 2.5 20h19L12 3Zm0 6v5m0 3v.01" />
  ),
  telemetry: (
    <path d="M3 12h4l3-7 4 14 3-7h4" />
  ),
  endpoints: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="1.5" />
      <path d="M8 20h8M12 16v4" />
    </>
  ),
};

function Icon({ name, size = 18 }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.6"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{ICONS[name]}</svg>
  );
}

export function Mark({ size = 22 }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden="true">
      <path d="M16 3 5 7v8c0 6.6 4.6 12.4 11 14 6.4-1.6 11-7.4 11-14V7z" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M16 9v14M11 13.5h10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function Rail({ view, onView, newAlerts, enrolling, connected }) {
  const items = [
    ["overview", "Overview"],
    ["alerts", "Cases", newAlerts],
    ["telemetry", "Telemetry"],
    ["endpoints", enrolling ? `Endpoints, ${enrolling} enrolling` : "Endpoints", 0, enrolling],
  ];
  return (
    <nav className="flex w-[60px] shrink-0 flex-col items-center bg-spine py-3" aria-label="Main">
      {/* the spine label, like the tab on a case folder */}
      <div className="mb-4 flex flex-col items-center gap-2 border-b border-spine-on pb-4" title="Aegis">
        <span className="rotate-180 font-cond text-[17px] font-extrabold leading-none tracking-[0.2em] text-spine-ink [writing-mode:vertical-rl]">AEGIS</span>
      </div>
      <div className="flex flex-col gap-1">
        {items.map(([key, label, badge, busy]) => {
          const on = view === key;
          return (
            <button key={key} onClick={() => onView(key)} aria-label={label} aria-current={on ? "page" : undefined}
              className={`group relative grid h-10 w-10 place-items-center rounded-lg transition-colors ${on ? "bg-spine-on text-spine-ink" : "text-spine-muted hover:bg-spine-on/60 hover:text-spine-ink"}`}>
              {on && <span className="absolute -left-[10px] top-2 bottom-2 w-[3px] rounded-r-full bg-spine-ink" />}
              <Icon name={key} />
              {busy > 0 && <span className="live-ring absolute right-1 top-1 h-2 w-2 rounded-full bg-ok text-ok" />}
              {badge > 0 && (
                <span className="absolute -right-0.5 -top-0.5 grid min-w-[17px] place-items-center rounded-full bg-crit px-1 text-[10px] font-semibold leading-[17px] text-white">
                  {badge > 99 ? "99+" : badge}
                </span>
              )}
              <span className="pointer-events-none absolute left-[52px] z-50 whitespace-nowrap rounded-md border border-line bg-raised px-2 py-1 text-xs text-text opacity-0 shadow-lg transition-opacity group-hover:opacity-100">
                {label}
              </span>
            </button>
          );
        })}
      </div>
      <ThemeToggle />
      <div className="mt-4" title={connected ? "Connected to backend" : "Reconnecting to backend"}>
        <span className={`block h-2 w-2 rounded-full ${connected ? "live-ring bg-ok text-ok" : "bg-crit"}`} />
      </div>
    </nav>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === "dark");
  const flip = () => {
    const next = !dark;
    setDark(next);
    if (next) document.documentElement.dataset.theme = "dark";
    else delete document.documentElement.dataset.theme;
    try { localStorage.setItem("aegis.theme", next ? "dark" : "light"); } catch {}
  };
  return (
    <button onClick={flip} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"} title={dark ? "Light theme" : "Dark theme"}
      className="mt-auto grid h-9 w-9 place-items-center rounded-lg text-spine-muted transition-colors hover:bg-spine-on/60 hover:text-spine-ink">
      {dark
        ? <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" /></svg>
        : <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" /></svg>}
    </button>
  );
}

export function TopBar({ title, subtitle, query, onQuery, searchRef, placeholder, scope, onClearScope, children }) {
  return (
    <div className="flex h-14 shrink-0 items-center gap-4 border-b border-line px-5">
      <div className="min-w-0">
        <h1 className="text-[15px] font-semibold leading-tight">{title}</h1>
        {subtitle && <p className="hidden truncate text-xs text-muted xl:block">{subtitle}</p>}
      </div>
      {scope && (
        <button onClick={onClearScope} title="Show all endpoints"
          className="flex items-center gap-1.5 rounded-md border border-accent/40 bg-accent/10 px-2 py-1 text-xs text-accent hover:bg-accent/15">
          Host: {scope}
          <span aria-hidden="true" className="text-accent/70">×</span>
        </button>
      )}
      <div className="ml-auto flex items-center gap-2">
        {children}
        <label className="relative flex items-center">
          <svg className="pointer-events-none absolute left-2.5 text-muted" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
          </svg>
          <span className="sr-only">Search</span>
          <input ref={searchRef} value={query} onChange={(e) => onQuery(e.target.value)} placeholder={placeholder}
            className="h-8 w-56 rounded-md border border-line xl:w-72 bg-surface pl-8 pr-10 text-[13px] outline-none transition-colors placeholder:text-muted focus:border-accent/60 focus:bg-raised" />
          <kbd className="pointer-events-none absolute right-2 rounded border border-line px-1 font-mono text-[10px] text-muted">/</kbd>
        </label>
      </div>
    </div>
  );
}

export function Sparkline({ values, width = 120, height = 28, color = "var(--color-accent)" }) {
  const max = Math.max(1, ...values);
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(height - 2 - (v / max) * (height - 4)).toFixed(1)}`);
  return (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="block h-[30px] w-full max-w-[160px] overflow-visible" aria-hidden="true">
      <polyline points={`0,${height} ${pts.join(" ")} ${width},${height}`} fill={color} opacity="0.12" />
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function Segmented({ options, value, onChange }) {
  return (
    <div className="inline-flex rounded-md border border-line bg-surface p-0.5" role="tablist">
      {options.map(([v, label, n]) => {
        const on = value === v;
        return (
          <button key={label} role="tab" aria-selected={on} onClick={() => onChange(v)}
            className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition-colors ${on ? "bg-raised text-text shadow-sm" : "text-muted hover:text-text-2"}`}>
            {label}
            {n !== undefined && <span className={`tabular-nums ${on ? "text-text-2" : "text-muted"}`}>{n}</span>}
          </button>
        );
      })}
    </div>
  );
}
