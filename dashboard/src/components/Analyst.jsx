import { useEffect, useRef, useState } from "react";
import { api } from "../lib/live.js";
import { findings } from "./Inspector.jsx";

const VERDICT = {
  malicious: { label: "Malicious", color: "var(--color-crit)" },
  suspicious: { label: "Suspicious", color: "var(--color-med)" },
  likely_benign: { label: "Likely benign", color: "var(--color-ok)" },
};

const NARRATE_KEY = "aegis.narrate";
const readNarrate = () => { try { return localStorage.getItem(NARRATE_KEY) === "1"; } catch { return false; } };
const spoken = new Set(); // analyses already read aloud this session, so re-renders never repeat one

function pickVoice() {
  const vs = window.speechSynthesis?.getVoices() || [];
  return vs.find((v) => /en-(GB|IN|US)/.test(v.lang) && /natural|premium|enhanced|daniel|samantha|google/i.test(v.name))
    || vs.find((v) => v.lang?.startsWith("en")) || null;
}

export function speak(text, onEnd) {
  const s = window.speechSynthesis;
  if (!s || !text) return false;
  s.cancel();
  const u = new SpeechSynthesisUtterance(text);
  const v = pickVoice();
  if (v) u.voice = v;
  u.rate = 1.02;
  u.onend = u.onerror = () => onEnd?.();
  s.speak(u);
  return true;
}

/** AI analyst write-up for one case: verdict, story, impact, recommended actions, read aloud on demand. */
export default function Analyst({ alert, tree, kills, autoNarrate = false }) {
  const a = alert?.analysis;
  const [busy, setBusy] = useState(false);
  const [talking, setTalking] = useState(false);
  const [narrate, setNarrate] = useState(readNarrate);
  const asked = useRef(new Set());

  const run = async (refresh = false) => {
    setBusy(true);
    try {
      const f = findings(alert, tree, kills);
      await api.post(`/api/alerts/${alert.id}/analyze${refresh ? "?refresh=1" : ""}`, f);
    } finally { setBusy(false); }
  };

  // write-up on first view, once the process graph has loaded (it feeds the evidence)
  useEffect(() => {
    if (!alert || a || tree === undefined || asked.current.has(alert.id)) return;
    asked.current.add(alert.id);
    run();
  }, [alert?.id, a, tree]);

  // narrate fresh write-ups on the lead case when the room has narration on
  useEffect(() => {
    if (!autoNarrate || !narrate || !a?.generated_at) return;
    const id = `${alert.id}:${a.generated_at}`;
    if (spoken.has(id) || Date.now() - Date.parse(a.generated_at) > 60_000) return;
    spoken.add(id);
    if (speak(a.narration, () => setTalking(false))) setTalking(true);
  }, [a?.generated_at, narrate, autoNarrate]);

  useEffect(() => () => window.speechSynthesis?.cancel(), []);

  const toggleTalk = () => {
    if (talking) { window.speechSynthesis?.cancel(); setTalking(false); return; }
    if (speak(a.narration, () => setTalking(false))) setTalking(true);
  };
  const toggleNarrate = () => {
    const next = !narrate;
    setNarrate(next);
    try { localStorage.setItem(NARRATE_KEY, next ? "1" : "0"); } catch {}
    if (!next) window.speechSynthesis?.cancel();
  };

  if (!alert) return null;
  const v = VERDICT[a?.verdict] || VERDICT.suspicious;

  return (
    <section aria-label="AI analyst" aria-busy={busy}>
      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-[13px] font-semibold">AI analyst</h3>
        {a && <span className="text-[11px] text-muted">
          {a.source === "groq" ? `${a.model?.split("/").pop()} · ${(a.latency_ms / 1000).toFixed(1)} s` : "template (no AI)"}
        </span>}
        <div className="ml-auto flex items-center gap-1">
          {autoNarrate && (
            <button onClick={toggleNarrate} aria-pressed={narrate} title="Read new cases aloud"
              className={`h-6 rounded-md px-2 text-[11px] ${narrate ? "bg-accent text-bg" : "text-muted hover:text-text"}`}>
              Narrate {narrate ? "on" : "off"}
            </button>
          )}
          {a && (
            <button onClick={toggleTalk} aria-label={talking ? "Stop reading" : "Read aloud"} title={talking ? "Stop" : "Read aloud"}
              className="grid h-6 w-6 place-items-center rounded-md text-text-2 hover:bg-hover hover:text-text">
              {talking
                ? <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><rect x="2" y="2" width="8" height="8" fill="currentColor" /></svg>
                : <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M2.5 6v4h2.5l3.5 3V3L5 6z" fill="currentColor" stroke="none" /><path d="M11 5.5a3.5 3.5 0 0 1 0 5M12.8 3.5a6 6 0 0 1 0 9" /></svg>}
            </button>
          )}
          {a && (
            <button onClick={() => run(true)} disabled={busy} title="Write it again"
              className="h-6 rounded-md px-2 text-[11px] text-muted hover:text-text disabled:opacity-50">Redo</button>
          )}
        </div>
      </div>

      {!a ? (
        <div className="border-l-2 border-line py-1 pl-3 text-xs text-muted">
          {busy || tree === undefined ? (
            <span className="flex items-center gap-2"><span className="h-3 w-3 animate-spin rounded-full border-2 border-line border-t-accent" /> Reading the evidence…</span>
          ) : (
            <button onClick={() => run()} className="text-accent underline-offset-2 hover:underline">Write the case summary</button>
          )}
        </div>
      ) : (
        <div className={`border-l-2 pl-3 transition-opacity ${busy ? "opacity-50" : ""}`} style={{ borderColor: v.color }}>
          <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide" style={{ color: v.color }}>
            {v.label}<span className="font-normal normal-case tracking-normal text-muted">{a.confidence} confidence</span>
          </div>
          <p className="mt-1 text-[14px] font-semibold leading-snug">{a.headline}</p>
          <p className="mt-1.5 text-[13px] leading-relaxed text-text-2">{a.story}</p>
          {a.impact && <p className="mt-1.5 text-xs leading-relaxed text-muted"><span className="font-semibold text-text-2">At risk: </span>{a.impact}</p>}
          {a.actions?.length > 0 && (
            <ol className="mt-3 space-y-1.5">
              {a.actions.map((x, i) => (
                <li key={x.action} className="grid grid-cols-[18px_1fr] text-xs">
                  <span className="font-mono text-muted">{i + 1}</span>
                  <span><span className="font-semibold">{x.label}.</span> <span className="text-text-2">{x.why}</span></span>
                </li>
              ))}
            </ol>
          )}
          <p className="mt-2.5 text-[11px] text-muted">Recommendations only. You confirm every action.{a.error ? ` ${a.error}; showing the template.` : ""}</p>
        </div>
      )}
    </section>
  );
}
