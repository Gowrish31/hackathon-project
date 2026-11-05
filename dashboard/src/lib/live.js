import { useEffect, useRef, useState } from "react";

const MAX_EVENTS = 2000;

export const api = {
  get: (path) => fetch(path).then((r) => r.json()),
  post: (path, body) =>
    fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json()),
  del: (path) => fetch(path, { method: "DELETE" }).then((r) => r.json()),
  patch: (path, body) =>
    fetch(path, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json()),
};

/** Initial load over REST, then live updates over the /ws WebSocket. */
export function useLive() {
  const [events, setEvents] = useState([]);
  const [agents, setAgents] = useState({});
  const [commands, setCommands] = useState({});
  const [cmdLog, setCmdLog] = useState({}); // every command seen over the socket, by id
  const [alerts, setAlerts] = useState([]);
  const [installs, setInstalls] = useState({}); // endpoint onboarding runs, by install id
  const [requests, setRequests] = useState({}); // join requests from Aegis Setup, by id
  const [toasts, setToasts] = useState([]);
  const [connected, setConnected] = useState(false);
  const [rate, setRate] = useState(Array(60).fill(0)); // events/sec, last 60s
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  const held = useRef([]);
  const tick = useRef(0);

  pausedRef.current = paused;

  useEffect(() => {
    api.get("/api/agents").then((list) => setAgents(Object.fromEntries(list.map((a) => [a.id, a]))));
    api.get("/api/events?limit=300").then(setEvents);
    api.get("/api/alerts?limit=300").then(setAlerts);
    api.get("/api/enroll/info").then((i) => {
      setInstalls(Object.fromEntries((i.installs || []).map((x) => [x.id, x])));
      setRequests(Object.fromEntries((i.requests || []).map((x) => [x.id, x])));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      const n = tick.current;
      tick.current = 0;
      setRate((r) => [...r.slice(1), n]);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let ws, retry, closed = false;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 1500);
      };
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data);
        if (msg.type === "events") {
          tick.current += msg.events.length;
          const fresh = msg.events.slice().reverse().map((e) => ({ ...e, _new: true }));
          if (pausedRef.current) held.current = [...fresh, ...held.current].slice(0, MAX_EVENTS);
          else setEvents((prev) => [...fresh, ...prev].slice(0, MAX_EVENTS));
        } else if (msg.type === "agent") {
          setAgents((prev) => ({ ...prev, [msg.agent.id]: msg.agent }));
        } else if (msg.type === "agent_removed") {
          setAgents((prev) => {
            const next = { ...prev };
            delete next[msg.agent_id];
            return next;
          });
          setInstalls((prev) => Object.fromEntries(Object.entries(prev).map(([k, v]) =>
            [k, v.agent_id === msg.agent_id ? { ...v, status: "removed" } : v])));
        } else if (msg.type === "join_request") {
          setRequests((prev) => ({ ...prev, [msg.request.id]: msg.request }));
        } else if (msg.type === "install") {
          setInstalls((prev) => ({ ...prev, [msg.install.id]: msg.install }));
        } else if (msg.type === "alert") {
          const a = msg.alert;
          setAlerts((prev) => {
            const i = prev.findIndex((x) => x.id === a.id);
            if (i === -1) return [{ ...a, _new: true }, ...prev];
            const next = prev.slice();
            next[i] = { ...prev[i], ...a };
            return next;
          });
          if (a.status === "open") {
            setToasts((prev) => (prev.some((t) => t.id === a.id) ? prev : [a, ...prev].slice(0, 4)));
            setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== a.id)), 9000);
          }
        } else if (msg.type === "command") {
          setCommands((prev) => ({ ...prev, [msg.command.agent_id]: msg.command }));
          setCmdLog((prev) => ({ ...prev, [msg.command.id]: { ...prev[msg.command.id], ...msg.command } }));
        }
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  const togglePause = () => {
    if (paused && held.current.length) {
      const h = held.current;
      held.current = [];
      setEvents((prev) => [...h, ...prev].slice(0, MAX_EVENTS));
    }
    setPaused((p) => !p);
  };

  const dismissToast = (id) => setToasts((prev) => prev.filter((t) => t.id !== id));
  const updateAlert = (a) => setAlerts((prev) => prev.map((x) => (x.id === a.id ? { ...x, ...a } : x)));

  return { events, agents, commands, cmdLog, alerts, installs, requests, toasts, dismissToast, updateAlert, connected, rate, paused,
    heldCount: held.current.length, togglePause };
}

export const isOnline = (agent) => agent?.last_seen && Date.now() - Date.parse(agent.last_seen) < 20_000;

export const fmtTime = (iso) => {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
};

export const CATEGORIES = {
  process:     { label: "Process",     color: "var(--c-process)" },
  network:     { label: "Network",     color: "var(--c-network)" },
  dns:         { label: "DNS",         color: "var(--c-dns)" },
  file:        { label: "File",        color: "var(--c-file)" },
  registry:    { label: "Registry",    color: "var(--c-registry)" },
  auth:        { label: "Sign-in",     color: "var(--c-auth)" },
  account:     { label: "Account",     color: "var(--c-account)" },
  persistence: { label: "Persistence", color: "var(--c-persistence)" },
  script:      { label: "PowerShell",  color: "var(--c-script)" },
  injection:   { label: "Injection",   color: "var(--color-crit)" },
  tamper:      { label: "Tamper",      color: "var(--color-crit)" },
  av:          { label: "Defender",    color: "var(--color-crit)" },
  ransomware:  { label: "Ransomware",  color: "var(--color-crit)" },
  system:      { label: "System",      color: "var(--c-other)" },
  other:       { label: "Other",       color: "var(--c-other)" },
};
export const catStyle = (c) => CATEGORIES[c] || CATEGORIES.other;

export const SEVERITY = {
  critical: { label: "Critical", color: "var(--color-crit)", rank: 4 },
  high:     { label: "High",     color: "var(--color-high)", rank: 3 },
  medium:   { label: "Medium",   color: "var(--color-med)", rank: 2 },
  low:      { label: "Low",      color: "var(--color-low)", rank: 1 },
};
export const sevStyle = (s) => SEVERITY[s] || SEVERITY.low;

export const STATUS = {
  open:         { label: "New",          color: "var(--color-text)" },
  acknowledged: { label: "Investigating", color: "var(--color-med)" },
  contained:    { label: "Contained",    color: "var(--color-ok)" },
  closed:       { label: "Resolved",     color: "var(--color-muted)" },
};
export const statusStyle = (s) => STATUS[s] || STATUS.open;

export const caseNo = (id) => `Case ${String(id).padStart(4, "0")}`;

export const basename = (p = "") => String(p).split("\\").pop().split("/").pop();

export const ago = (iso) => {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (isNaN(s)) return "";
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

/** Decode a PowerShell -EncodedCommand argument (base64 of UTF-16LE). */
export function decodeEncoded(cmd = "") {
  const m = String(cmd).match(/\s-e(?:c|nc|ncodedcommand)?\s+["']?([A-Za-z0-9+/=]{8,})/i);
  if (!m) return null;
  try {
    const bin = atob(m[1]);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-16le").decode(bytes).replace(/\0/g, "").trim() || null;
  } catch { return null; }
}
