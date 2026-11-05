import { api, decodeEncoded, fmtTime } from "../lib/live.js";
import { KIND, target } from "./ProcessGraph.jsx";

const flatten = (root) => {
  const out = [];
  const walk = (n, parent) => { out.push({ n, parent }); n.children.forEach((c) => walk(c, n)); };
  if (root) walk(root, null);
  return out;
};
const uniq = (xs) => [...new Set(xs)];
const list = (xs, max = 3) => (xs.length > max ? `${xs.slice(0, max).join(", ")} and ${xs.length - max} more` : xs.join(", "));
const secs = (a, b) => ((Date.parse(b) - Date.parse(a)) / 1000).toFixed(2);

/** Split the evidence into what the telemetry proves and what it can't tell us. */
export function findings(alert, tree, kills = []) {
  const known = [], open = [];
  const ctx = alert.context || {};
  const all = flatten(tree?.root);
  const focus = all.find((x) => x.n.focus);
  const done = kills.find((k) => k.status === "done");

  known.push({ title: `${alert.rule_id} matched`, detail: alert.title });

  if (focus) {
    const f = focus.n;
    known.push({ title: `${f.name} started`, detail: `PID ${f.pid}${focus.parent ? `, launched by ${focus.parent.name}` : ""}${f.user ? ` as ${f.user}` : ""}` });
    const decoded = decodeEncoded(f.cmd);
    if (decoded) known.push({ title: "Hidden command decoded", detail: decoded, mono: true });
    if (/high|system/i.test(f.integrity || "")) known.push({ title: "Ran with administrator rights", detail: `Integrity level ${f.integrity}` });

    const sub = all.filter((x) => x.n === f || flatten(f).some((y) => y.n === x.n));
    const acts = sub.flatMap((x) => x.n.activity);
    const by = (k) => uniq(acts.filter((a) => a.kind === k).map(target));
    const kids = flatten(f).slice(1).map((x) => x.n.name);
    if (kids.length) known.push({ title: "Started child processes", detail: list(uniq(kids)) });
    if (by("network").length) known.push({ title: "Connected out", detail: list(by("network")), mono: true });
    if (by("dns").length) known.push({ title: "Looked up domains", detail: list(by("dns")), mono: true });
    if (by("file").length) known.push({ title: `Wrote ${by("file").length} file${by("file").length === 1 ? "" : "s"}`, detail: list(by("file")), mono: true });
    if (by("registry").length) known.push({ title: "Changed the registry", detail: list(by("registry")), mono: true });
    if (by("access").length) known.push({ title: "Opened another process's memory", detail: list(by("access")), mono: true, tone: "crit" });

    if (ctx.Action === "killed" && ctx.KillMs) known.push({ title: "Killed by the ransomware kill-switch", detail: `On the endpoint, ${ctx.KillMs} ms after the canary tripped. ${ctx.FilesAffected} files hit.`, tone: "ok" });
    else if (done) known.push({ title: "Killed by Aegis", detail: `${secs(done.created_at, done.completed_at)} s, click to confirmed kill`, tone: "ok" });
    else if (f.exited) known.push({ title: "Process exited on its own", detail: fmtTime(f.exited) });
    else open.push({ title: "Whether it is still running", detail: "No exit recorded. Kill it to be sure." });

    if (by("network").length) open.push({ title: "Whether data left the host", detail: "Connections logged. Payloads not inspected." });
    if (by("access").some((t) => /lsass/i.test(t))) open.push({ title: "Whether credentials were extracted", detail: "LSASS opened for reading. The read itself leaves no event." });
    if (decoded && /http|iex|download|webclient|invoke-expression/i.test(decoded)) open.push({ title: "What the fetched code did", detail: "Pulled from the network, never written to disk." });
    const stub = all.find((x) => x.n.stub);
    if (stub) open.push({ title: `How ${stub.n.name} started`, detail: "Already running when logging began." });
  } else if (ctx.ScriptBlockText) {
    const url = String(ctx.ScriptBlockText).match(/https?:\/\/[^\s'")]+/i);
    known.push({ title: "PowerShell script recorded", detail: String(ctx.ScriptBlockText).slice(0, 140), mono: true });
    if (url) {
      known.push({ title: "Script references a URL", detail: url[0], mono: true });
      open.push({ title: "Whether the download succeeded", detail: "No connection tied to this script yet." });
      open.push({ title: "What the downloaded content did", detail: "Script logging shows the command, not the result." });
    }
  }
  return { known, open };
}

function Row({ label, children, mono }) {
  return (
    <div className="grid grid-cols-[84px_1fr] gap-3 py-1.5 text-xs">
      <dt className="text-muted">{label}</dt>
      <dd className={`min-w-0 break-all ${mono ? "font-mono text-text-2" : "text-text"}`}>{children}</dd>
    </div>
  );
}

/** Right-hand panel: the selected graph item up top, then the analyst's ledger. */
export default function Inspector({ alert, tree, kills, selected, onOpenEvent, compact = false }) {
  const { known, open } = findings(alert, tree, kills);
  const focus = flatten(tree?.root).find((x) => x.n.focus)?.n;
  const sel = selected || (focus ? { type: "process", node: focus } : null);

  const openEvent = (id) => id && api.get(`/api/events/${id}`).then((e) => e?.id && onOpenEvent(e));

  return (
    <div className="flex flex-col gap-5">
      {sel && (
        <section>
          <div className="flex items-start gap-3">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-raised"
              style={{ color: sel.type === "activity" ? KIND[sel.group.kind]?.color : "var(--color-text-2)" }}>
              {sel.type === "activity"
                ? <span className="h-2.5 w-2.5 rounded-full" style={{ background: "currentColor" }} />
                : <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><path d="M7 9l3 3-3 3M13 15h4" /></svg>}
            </span>
            <div className="min-w-0">
              <h3 className="truncate font-semibold">{sel.type === "activity" ? sel.group.label : sel.node.name}</h3>
              <p className="text-xs text-muted">
                {sel.type === "activity"
                  ? `${KIND[sel.group.kind]?.label || sel.group.kind}, ${sel.group.count} event${sel.group.count === 1 ? "" : "s"} from ${sel.node.name}`
                  : sel.node.stub ? "Inferred from its child" : selected ? `PID ${sel.node.pid || "unknown"}` : "Flagged process"}
              </p>
            </div>
          </div>
          <dl className="mt-3 divide-y divide-line-soft border-y border-line-soft">
            {sel.type === "activity" ? (
              <>
                <Row label="First seen">{fmtTime(sel.group.ts)}</Row>
                {sel.group.items.slice(0, 4).map((a) => <Row key={a.id} label={fmtTime(a.ts).slice(0, 8)} mono>{a.summary}</Row>)}
              </>
            ) : (
              <>
                {sel.node.pid && <Row label="PID" mono>{sel.node.pid}</Row>}
                {sel.node.user && <Row label="User" mono>{sel.node.user}</Row>}
                {sel.node.integrity && <Row label="Integrity">{sel.node.integrity}</Row>}
                {sel.node.ts && <Row label="Started">{fmtTime(sel.node.ts)}</Row>}
                <Row label="Path" mono>{sel.node.image}</Row>
                {!compact && sel.node.cmd && <Row label="Command" mono>{sel.node.cmd}</Row>}
              </>
            )}
          </dl>
          {(sel.type === "activity" ? sel.group.items[0]?.id : sel.node.event_id) && (
            <button onClick={() => openEvent(sel.type === "activity" ? sel.group.items[0].id : sel.node.event_id)}
              className="mt-3 h-8 w-full rounded-md border border-line text-xs text-text-2 transition-colors hover:border-text-2/40 hover:text-text">
              Raw event
            </button>
          )}
        </section>
      )}

      <section>
        <h3 className="mb-2 text-[13px] font-semibold">Established</h3>
        <ul className="space-y-2.5">
          {known.map((k, i) => (
            <li key={i} className="flex gap-2.5">
              <svg className="mt-0.5 shrink-0" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"
                style={{ color: k.tone === "crit" ? "var(--color-crit)" : "var(--color-ok)" }}>
                <circle cx="8" cy="8" r="7" fill="currentColor" opacity="0.16" />
                <path d="m4.8 8.2 2.1 2.1 4.3-4.6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <div className="min-w-0">
                <div className={`text-[13px] ${k.tone === "ok" ? "text-ok" : ""}`}>{k.title}</div>
                <div className={`mt-0.5 break-all text-xs text-muted ${k.mono ? "font-mono" : ""}`}>{k.detail}</div>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3 className="mb-2 text-[13px] font-semibold text-warn">Open questions</h3>
        {open.length === 0 ? <p className="text-xs text-muted">None.</p> : (
          <ul className="space-y-2.5">
            {open.map((k, i) => (
              <li key={i} className="flex gap-2.5">
                <svg className="mt-0.5 shrink-0 text-warn" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M8 1.8 15 14H1z" fill="currentColor" opacity="0.16" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                  <path d="M8 6.2v3.6M8 11.6v.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                </svg>
                <div className="min-w-0">
                  <div className="text-[13px]">{k.title}</div>
                  <div className="mt-0.5 text-xs text-muted">{k.detail}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
