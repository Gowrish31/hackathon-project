import { SEVERITY } from "./live.js";

const GAP_MS = 15 * 60 * 1000;            // alerts on one host within 15 min of each other form one incident
const STATUS_ORDER = ["open", "acknowledged", "contained", "closed"];

/** Group alerts into incidents: same endpoint, chained by time. */
export function groupIncidents(alerts) {
  const byAgent = {};
  for (const a of alerts) (byAgent[a.agent_id] ||= []).push(a);

  const incidents = [];
  for (const list of Object.values(byAgent)) {
    list.sort((x, y) => x.ts.localeCompare(y.ts));
    let cur = null;
    for (const a of list) {
      if (!cur || Date.parse(a.ts) - Date.parse(cur.at(-1).ts) > GAP_MS) incidents.push((cur = []));
      cur.push(a);
    }
  }
  return incidents.map(build);
}

function build(chrono) {
  const alerts = chrono.slice().reverse(); // newest first
  const severity = chrono.reduce((s, a) => (SEVERITY[a.severity].rank > SEVERITY[s].rank ? a.severity : s), "low");
  const status = STATUS_ORDER[Math.min(...chrono.map((a) => STATUS_ORDER.indexOf(a.status)).filter((i) => i >= 0))] || "open";
  const rules = [...new Set(chrono.map((a) => a.rule_title))];
  const tactics = [...new Set(chrono.map((a) => a.tactic))];
  // lead with what still needs attention: unresolved first, then severity, then newest
  const primary = alerts.slice().sort((x, y) =>
    (x.status === "closed") - (y.status === "closed") || SEVERITY[y.severity].rank - SEVERITY[x.severity].rank)[0];
  const host = chrono[0].hostname;
  return {
    id: chrono[0].id,
    alerts,
    primary,
    agent_id: chrono[0].agent_id,
    hostname: host,
    severity,
    status,
    first_ts: chrono[0].ts,
    last_ts: chrono.at(-1).ts,
    rules,
    tactics,
    techniques: [...new Map(chrono.map((a) => [a.technique, a])).values()].map((a) => ({ id: a.technique, name: a.technique_name })),
    title: rules.length === 1 ? rules[0] : tactics.length > 1 ? `${tactics.join(" → ")} on ${host}` : `${primary.rule_title} and ${rules.length - 1} related`,
    _new: chrono.some((a) => a._new),
  };
}

export const incidentInTab = (inc, tab) =>
  !tab || (tab === "active" ? inc.status === "open" || inc.status === "acknowledged" : inc.status === tab);
