import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, isOnline } from "../lib/live.js";

/** "Let judges try it": opens a time-limited public link to the drills and shows it as a big QR code. */
export default function JudgeMode({ agents }) {
  const [open, setOpen] = useState(false);
  const [session, setSession] = useState(null);
  const [svg, setSvg] = useState("");
  const [error, setError] = useState(null);

  const url = session?.token ? `${location.origin}/judge/${session.token}` : "";
  const target = Object.values(agents).filter(isOnline).sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""))[0];
  const host = session ? agents[session.agent_id]?.hostname : null;

  useEffect(() => { api.get("/api/judge/session").then((s) => setSession(s?.token ? s : null)).catch(() => {}); }, [open]);
  useEffect(() => {
    if (!url) return setSvg("");
    QRCode.toString(url, { type: "svg", margin: 1, errorCorrectionLevel: "M", color: { dark: "#15181b", light: "#f3f4ef" } }).then(setSvg);
  }, [url]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const start = async () => {
    setError(null);
    if (!target) return setError("No endpoint is reporting. Wake the demo laptop first.");
    const s = await api.post("/api/judge/session", { agent_id: target.id });
    if (s?.token) setSession(s); else setError(s?.detail || "Could not open a judge session.");
  };
  const end = async () => { await api.del("/api/judge/session"); setSession(null); };

  return (
    <>
      <button onClick={() => setOpen(true)} title="Show a QR code judges can scan to attack the laptop"
        className="flex h-8 items-center gap-1.5 rounded-md border border-line px-3 text-[13px] text-text-2 hover:border-text-2/40 hover:text-text">
        <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M1 1h6v6H1zm2 2v2h2V3zM9 1h6v6H9zm2 2v2h2V3zM1 9h6v6H1zm2 2v2h2v-2zM9 9h2v2H9zm2 2h2v2h-2zm2-2h2v2h-2zm0 4h2v2h-2zm-4 0h2v2H9z" />
        </svg>
        Judges{session ? " · live" : ""}
      </button>

      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-spine/70 p-4" onClick={() => setOpen(false)} role="dialog" aria-modal="true" aria-label="Judge mode">
          <div className="w-full max-w-[560px] rounded-lg border border-line bg-bg p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start">
              <div>
                <h2 className="font-cond text-[26px] font-semibold leading-tight">Attack our laptop</h2>
                <p className="mt-1 text-sm text-text-2">Scan with your phone, pick an attack, watch the console catch it.</p>
              </div>
              <button onClick={() => setOpen(false)} aria-label="Close" className="ml-auto grid h-8 w-8 place-items-center rounded-md text-muted hover:bg-hover hover:text-text">✕</button>
            </div>

            {session ? (
              <>
                <div className="mx-auto mt-5 w-full max-w-[340px] [&_svg]:h-auto [&_svg]:w-full" dangerouslySetInnerHTML={{ __html: svg }} />
                <p className="mt-3 break-all text-center font-mono text-xs text-muted">{url}</p>
                <div className="mt-5 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line-soft pt-4 text-xs text-text-2">
                  <span>Target <b className="font-mono font-medium text-text">{host || session.agent_id.slice(0, 8)}</b></span>
                  <span>{session.runs}/{session.max_runs} drills used</span>
                  <span>Link expires in {Math.max(0, Math.round(session.expires_in / 60))} min</span>
                  <button onClick={end} className="ml-auto h-8 rounded-md border border-crit/50 px-3 text-[13px] text-crit hover:bg-crit/10">End session</button>
                </div>
              </>
            ) : (
              <div className="mt-6">
                <p className="text-sm text-text-2">
                  Opens a link that works for 60 minutes without the console password. It can only run the three harmless drills,
                  one at a time, on <b className="font-mono font-medium text-text">{target?.hostname || "the demo laptop"}</b>.
                </p>
                {error && <p className="mt-3 text-sm text-crit">{error}</p>}
                <button onClick={start} className="mt-4 h-9 rounded-md bg-accent px-4 text-sm font-medium text-bg hover:brightness-110">Open judge session</button>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
