import { useEffect, useMemo, useRef, useState } from "react";
import { useLive, isOnline, SEVERITY, api, eventCategory } from "./lib/live.js";
import { Rail, TopBar, Segmented } from "./components/Shell.jsx";
import ThreatTimeline from "./components/Timeline.jsx";
import Overview from "./components/Overview.jsx";
import { runValidation } from "./components/Verify.jsx";
import EventFeed, { CategoryFilter } from "./components/EventFeed.jsx";
import EventDetail from "./components/EventDetail.jsx";
import Endpoints from "./components/AgentPanel.jsx";
import { IncidentQueue, IncidentDetail, AlertToasts } from "./components/Alerts.jsx";
import { groupIncidents, incidentInTab } from "./lib/incidents.js";

const STATUS_TABS = [
  ["active", "Active"],
  ["contained", "Contained"],
  ["closed", "Resolved"],
  [null, "All"],
];

export default function App() {
  const live = useLive();
  const [view, setView] = useState("overview");
  const [kick, setKick] = useState(0);        // tells the Verify panel a run just started
  const [testMsg, setTestMsg] = useState(null);
  const [scope, setScope] = useState(null);          // agent id
  const [category, setCategory] = useState(null);
  const [statusTab, setStatusTab] = useState("active");
  const [sevFilter, setSevFilter] = useState(null);
  const [query, setQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [flash, setFlash] = useState(false);
  const [follow, setFollow] = useState(() => {
    try { return localStorage.getItem("aegis.follow") !== "0"; } catch { return true; }
  });
  useEffect(() => { try { localStorage.setItem("aegis.follow", follow ? "1" : "0"); } catch {} }, [follow]);
  const [, tick] = useState(0);
  const seenToasts = useRef(new Set());
  const searchRef = useRef(null);
  const [response, setResponse] = useState(null);
  const [adding, setAdding] = useState(false);       // "Add endpoint" panel open
  const seenInstalls = useRef(new Set());

  // a machine starts enrolling: bring the onboarding tracker on screen (follow mode).
  // Only runs that are still in progress and began in the last minute count, so reloading the page doesn't jump.
  useEffect(() => {
    const fresh = Object.values(live.installs).filter((i) => !seenInstalls.current.has(i.id) &&
      i.status === "installing" && Date.now() - Date.parse(i.started_at) < 60_000);
    Object.keys(live.installs).forEach((id) => seenInstalls.current.add(id));
    if (fresh.length && follow) { setView("endpoints"); setAdding(true); }
  }, [live.installs]);
  // a machine running Aegis Setup asks to join: someone has to approve it, so show it (follow mode)
  const seenRequests = useRef(new Set());
  useEffect(() => {
    const fresh = Object.values(live.requests).filter((r) => !seenRequests.current.has(r.id) && r.status === "pending");
    Object.keys(live.requests).forEach((id) => seenRequests.current.add(id));
    if (fresh.length && follow) { setView("endpoints"); setAdding(true); }
  }, [live.requests]);
  const awaiting = Object.values(live.requests).filter((r) => r.status === "pending" && Date.now() - Date.parse(r.created_at) < 600_000).length;
  const enrolling = awaiting + Object.values(live.installs).filter((i) => i.status === "installing" || i.status === "online").length;

  // response stats: on load and whenever a command changes state
  useEffect(() => {
    api.get("/api/response/summary").then(setResponse).catch(() => {});
  }, [live.cmdLog]);

  // keep relative timestamps fresh
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 15000);
    return () => clearInterval(id);
  }, []);

  // a new detection lands: jump to it (follow mode), and flash red if it's critical
  useEffect(() => {
    const fresh = live.toasts.filter((t) => !seenToasts.current.has(t.id));
    fresh.forEach((t) => seenToasts.current.add(t.id));
    if (follow && fresh.length) {
      const top = fresh.slice().sort((a, b) => SEVERITY[b.severity].rank - SEVERITY[a.severity].rank)[0];
      setView((v) => (v === "overview" ? v : "alerts"));
      setStatusTab("active");
      setSevFilter(null);
      setSelectedEvent(null);
      setSelectedAlertId(top.id);
    }
    if (fresh.some((t) => t.severity === "critical")) {
      setFlash(true);
      const id = setTimeout(() => setFlash(false), 2200);
      return () => clearTimeout(id);
    }
  }, [live.toasts]);

  const q = query.trim().toLowerCase();

  // ---- telemetry
  const scopedEvents = useMemo(
    () => (scope ? live.events.filter((e) => e.agent_id === scope) : live.events), [live.events, scope]);
  const counts = useMemo(() => {
    const c = {};
    for (const e of scopedEvents) {
      const kind = eventCategory(e);
      c[kind] = (c[kind] || 0) + 1;
    }
    return c;
  }, [scopedEvents]);
  const visibleEvents = useMemo(() => scopedEvents.filter(
    (e) => (!category || eventCategory(e) === category) &&
      (!q || e.summary.toLowerCase().includes(q) || JSON.stringify(e.data).toLowerCase().includes(q))
  ), [scopedEvents, category, q]);

  // ---- alerts
  const scopedAlerts = useMemo(
    () => (scope ? live.alerts.filter((a) => a.agent_id === scope) : live.alerts), [live.alerts, scope]);
  const incidents = useMemo(() => groupIncidents(scopedAlerts), [scopedAlerts]);
  const visibleIncidents = useMemo(() => incidents
    .filter((inc) => incidentInTab(inc, statusTab) && (!sevFilter || inc.severity === sevFilter) &&
      (!q || inc.alerts.some((a) => `${a.title} ${a.rule_title} ${a.technique} ${a.tactic} ${a.hostname} ${JSON.stringify(a.context)}`.toLowerCase().includes(q))))
    .sort((a, b) => (statusTab === "active"
      ? SEVERITY[b.severity].rank - SEVERITY[a.severity].rank || b.last_ts.localeCompare(a.last_ts)
      : b.last_ts.localeCompare(a.last_ts))),
  [incidents, statusTab, sevFilter, q]);
  const newAlerts = live.alerts.filter((a) => a.status === "open").length;
  const pickedAlert = live.alerts.find((a) => a.id === selectedAlertId);
  const selectedIncident = (pickedAlert && visibleIncidents.find((inc) => inc.alerts.some((a) => a.id === pickedAlert.id)))
    || visibleIncidents[0] || null;
  const selectedAlert = selectedIncident
    ? selectedIncident.alerts.find((a) => a.id === pickedAlert?.id) || selectedIncident.primary
    : null;

  const agentList = Object.values(live.agents);
  const online = agentList.filter(isOnline).length;

  const openAlertId = (id) => {
    const a = live.alerts.find((x) => x.id === id);
    if (a) openAlert(a);
    else { setView("alerts"); setStatusTab(null); setSelectedAlertId(id); }
  };
  const testProtection = async () => {
    setView("overview");
    setTestMsg(null);
    const v = await runValidation(live.agents);
    if (v?.error || v?.detail) setTestMsg(v.error || v.detail);
    setKick((k) => k + 1);
  };

  const openAlert = (a) => {
    setView("alerts");
    setSelectedEvent(null);
    setStatusTab(null);
    setSevFilter(null);
    setSelectedAlertId(a.id);
  };

  // keyboard: "/" search, j/k move through alerts, Esc clears
  useEffect(() => {
    const onKey = (e) => {
      const typing = /INPUT|TEXTAREA/.test(document.activeElement?.tagName);
      if ((e.key === "/" || (e.key === "k" && (e.metaKey || e.ctrlKey))) && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "Escape") {
        if (typing) document.activeElement.blur();
        else if (selectedEvent) setSelectedEvent(null);
      } else if (!typing && view === "alerts" && (e.key === "j" || e.key === "k")) {
        const i = visibleIncidents.findIndex((inc) => inc.id === selectedIncident?.id);
        const next = visibleIncidents[Math.min(visibleIncidents.length - 1, Math.max(0, i + (e.key === "j" ? 1 : -1)))];
        if (next) setSelectedAlertId(next.primary.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, visibleIncidents, selectedIncident, selectedEvent]);

  const scopeName = scope ? live.agents[scope]?.hostname || scope.slice(0, 8) : null;
  const titles = {
    overview: ["Overview", null],
    alerts: ["Cases", null],
    telemetry: ["Telemetry", null],
    endpoints: ["Endpoints", awaiting ? `${awaiting} waiting for approval` : enrolling ? `${enrolling} enrolling now` : `${online} of ${agentList.length} reporting`],
  };

  return (
    <div className="flex h-full">
      {flash && <div className="crit-flash pointer-events-none fixed inset-0 z-40" />}
      <Rail view={view} onView={(v) => { setView(v); setQuery(""); }} newAlerts={newAlerts} enrolling={enrolling} connected={live.connected} />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar title={titles[view][0]} subtitle={titles[view][1]} query={query} onQuery={setQuery} searchRef={searchRef}
          placeholder={view === "alerts" ? "Search alerts, hosts, techniques" : view === "telemetry" ? "Search processes, command lines, IPs" : "Search"}
          scope={scopeName} onClearScope={() => setScope(null)}>
          {testMsg && <span className="max-w-[260px] truncate text-xs text-crit" title={testMsg}>{testMsg}</span>}
          <button onClick={testProtection}
            className="flex h-8 shrink-0 items-center gap-2 whitespace-nowrap rounded-md bg-accent px-3.5 text-[13px] font-medium text-bg transition hover:brightness-110">
            <svg width="10" height="10" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 1.5v9l7.5-4.5z" fill="currentColor" /></svg>
            Run drill
          </button>
          {(view === "alerts" || view === "overview" || view === "endpoints") && (
            <button onClick={() => setFollow((f) => !f)} aria-pressed={follow}
              title="Jump to each new case as it opens"
              className={`flex h-8 shrink-0 items-center gap-2 whitespace-nowrap rounded-md border px-3 text-[13px] ${follow ? "border-accent/40 text-text" : "border-line text-muted hover:text-text-2"}`}>
              <span className={`relative h-3.5 w-6 rounded-full transition-colors ${follow ? "bg-accent" : "bg-line"}`}>
                <span className={`absolute top-0.5 h-2.5 w-2.5 rounded-full bg-bg transition-all ${follow ? "left-[12px]" : "left-0.5"}`} />
              </span>
              <span>Follow</span>
            </button>
          )}
          {view === "telemetry" && (
            <button onClick={live.togglePause}
              className={`h-8 rounded-md border px-3 text-[13px] ${live.paused ? "border-warn/50 bg-warn/10 text-warn" : "border-line text-text-2 hover:text-text"}`}>
              {live.paused ? `Resume stream (${live.heldCount} waiting)` : "Pause stream"}
            </button>
          )}
        </TopBar>

        {view !== "endpoints" && (
          <ThreatTimeline alerts={scopedAlerts} incidents={incidents} events={scopedEvents} response={response}
            agentsOnline={online} agentsTotal={agentList.length} onOpen={openAlert}
            onSeverity={(s) => { setView("alerts"); setStatusTab("active"); setSevFilter(sevFilter === s ? null : s); }} />
        )}

        <div className="flex min-h-0 flex-1">
          {view === "overview" && (
            <>
              <Overview incidents={incidents} agents={live.agents} events={scopedEvents} cmdLog={live.cmdLog} kick={kick}
                onOpenAlert={openAlertId} onOpenEvent={setSelectedEvent} onRunTest={testProtection} />
              {selectedEvent && <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
            </>
          )}

          {view === "alerts" && (
            <>
              <div className="flex w-[300px] shrink-0 flex-col border-r border-line xl:w-[360px] 2xl:w-[400px]">
                <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
                  <Segmented value={statusTab} onChange={(v) => { setStatusTab(v); setSelectedAlertId(null); }}
                    options={STATUS_TABS.map(([v, l]) => [v, l, incidents.filter((inc) => incidentInTab(inc, v)).length])} />
                  {sevFilter && (
                    <button onClick={() => setSevFilter(null)} className="ml-auto text-xs text-accent hover:underline">
                      {SEVERITY[sevFilter].label} only ×
                    </button>
                  )}
                </div>
                <IncidentQueue incidents={visibleIncidents} selectedId={selectedIncident?.id}
                  onSelect={(inc) => { setSelectedEvent(null); setSelectedAlertId(inc.primary.id); }} />
              </div>
              <div key={selectedIncident?.id ?? "none"} className="arrive flex min-w-0 flex-1">
              <IncidentDetail incident={selectedIncident} alert={selectedAlert} onSelectAlert={setSelectedAlertId}
                agents={live.agents} cmdLog={live.cmdLog} onUpdate={live.updateAlert} onOpenEvent={setSelectedEvent} />
              </div>
              {selectedEvent && <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
            </>
          )}

          {view === "telemetry" && (
            <>
              <main className="flex min-w-0 flex-1 flex-col">
                <div className="border-b border-line px-4 py-2"><CategoryFilter counts={counts} active={category} onChange={setCategory} /></div>
                <EventFeed events={visibleEvents} selectedId={selectedEvent?.id} onSelect={setSelectedEvent} />
              </main>
              {selectedEvent && <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
            </>
          )}

          {view === "endpoints" && (
            <Endpoints agents={live.agents} commands={live.commands} cmdLog={live.cmdLog} alerts={live.alerts} events={live.events} installs={live.installs}
              requests={live.requests} adding={adding} onAdding={setAdding} scope={scope} onOpenAlert={openAlert}
              onScope={(id) => { setScope(id); if (id) setView("alerts"); }} />
          )}
        </div>
      </div>
      <AlertToasts toasts={live.toasts} onOpen={openAlert} onDismiss={live.dismissToast} />
    </div>
  );
}
