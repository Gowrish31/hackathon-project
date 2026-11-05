import { basename, decodeEncoded, sevStyle } from "../lib/live.js";

/**
 * Reconstructs "who did what to what" from an alert's context fields,
 * in the spirit of Defender's alert story / Falcon's process tree.
 */
export function buildStory(alert) {
  const c = alert.context || {};
  const nodes = [];

  if (c.ParentImage) {
    nodes.push({ kind: "process", name: basename(c.ParentImage), detail: c.ParentCommandLine || c.ParentImage, role: "parent" });
  }

  const actorImage = c.SourceImage || c.Image;
  if (actorImage) {
    nodes.push({
      kind: "process", name: basename(actorImage), detail: c.CommandLine || actorImage,
      pid: c.SourceProcessId || c.ProcessId, user: c.User || c.SourceUser, role: "actor",
      edge: nodes.length ? "launched" : null, decoded: decodeEncoded(c.CommandLine),
    });
  } else if (c.ScriptBlockText) {
    nodes.push({ kind: "script", name: "PowerShell script block", detail: c.ScriptBlockText, role: "actor" });
  } else if (c.IpAddress && c.TargetUserName) {
    nodes.push({ kind: "network", name: c.IpAddress, detail: "Remote sign-in source", role: "actor" });
  } else if (c.SubjectUserName) {
    nodes.push({ kind: "user", name: c.SubjectUserName, detail: "Account that made the change", role: "actor" });
  }

  const target = (kind, name, detail, edge) => nodes.push({ kind, name, detail, edge, role: "target" });
  if (c.TargetImage) target("process", basename(c.TargetImage), c.TargetImage,
    /lsass/i.test(c.TargetImage) ? "read memory of" : "opened a handle to");
  if (c.TargetFilename) target("file", basename(c.TargetFilename), c.TargetFilename, "wrote");
  if (c.TargetObject) target("registry", basename(c.TargetObject), `${c.TargetObject}${c.Details ? `  =  ${c.Details}` : ""}`, "set");
  if (c.DestinationIp) target("network", `${c.DestinationIp}${c.DestinationPort ? `:${c.DestinationPort}` : ""}`, c.DestinationHostname || "Outbound connection", "connected to");
  if (c.QueryName) target("network", c.QueryName, "DNS lookup", "resolved");
  if (c.TaskName) target("task", basename(c.TaskName), c.TaskName, "scheduled");
  if (c.ServiceName) target("task", c.ServiceName, c.ImagePath || "Windows service", "installed");
  if (c.TargetUserName && !c.IpAddress) target("user", c.TargetUserName, c.MemberName ? `Group change: ${c.MemberName}` : "Account", c.MemberName ? "added to group" : "changed");
  if (c.TargetUserName && c.IpAddress) target("user", c.TargetUserName, "Targeted account", "tried to sign in as");

  if (!actorImage && c.ScriptBlockText) {
    const url = String(c.ScriptBlockText).match(/https?:\/\/[^\s'")]+/i);
    if (url) target("network", new URL(url[0]).host, url[0], "downloaded from");
  }
  return nodes;
}

const GLYPH = {
  process: <><rect x="4" y="5" width="16" height="14" rx="2" /><path d="M8 10l2.5 2L8 14M12.5 14H16" /></>,
  script: <><path d="M7 4h8l4 4v12H7z" /><path d="M15 4v4h4M10 13h6M10 16h4" /></>,
  file: <><path d="M7 4h7l4 4v12H7z" /><path d="M14 4v4h4" /></>,
  registry: <><rect x="4" y="4" width="7" height="7" rx="1" /><rect x="13" y="4" width="7" height="7" rx="1" /><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="13" y="13" width="7" height="7" rx="1" /></>,
  network: <><circle cx="12" cy="12" r="8" /><path d="M4 12h16M12 4c2.5 2.5 2.5 13.5 0 16M12 4c-2.5 2.5-2.5 13.5 0 16" /></>,
  user: <><circle cx="12" cy="8.5" r="3.5" /><path d="M5 20c1-4 4-5.5 7-5.5s6 1.5 7 5.5" /></>,
  task: <><circle cx="12" cy="12" r="8" /><path d="M12 7.5V12l3 2" /></>,
};

export default function AttackStory({ alert, terminated }) {
  const nodes = buildStory(alert);
  if (!nodes.length) return null;
  const sev = sevStyle(alert.severity);
  const contained = terminated ?? alert.status === "contained";

  return (
    <ol className="relative">
      {nodes.map((n, i) => {
        const actor = n.role === "actor";
        const killed = actor && contained && n.kind === "process";
        const tone = killed ? "var(--color-ok)" : actor ? sev.color : "var(--color-muted)";
        return (
          <li key={i} className="relative">
            {i > 0 && (
              <div className="flex h-8 items-center pl-11">
                <span className="absolute left-[16px] w-px bg-line" style={{ top: 0, height: 32 }} />
                <span className="text-xs italic text-muted">{n.edge || "then"}</span>
              </div>
            )}
            <div className="relative pl-11">
            {i < nodes.length - 1 && <span className="absolute left-[16px] top-8 -bottom-px w-px bg-line" />}
            <span className="absolute left-0 top-0 grid h-8 w-8 place-items-center rounded-lg border bg-surface"
              style={{ borderColor: actor ? tone : "var(--color-line)", color: tone, boxShadow: actor && !killed ? `0 0 0 3px color-mix(in srgb, ${tone} 16%, transparent)` : "none" }}>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                {GLYPH[n.kind] || GLYPH.process}
              </svg>
            </span>

            <div className={`relative rounded-lg ${actor ? "border border-line bg-surface px-3 py-2.5" : "px-0 py-1"}`}>
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className={`font-semibold ${killed ? "text-text-2 line-through decoration-ok/70" : ""}`}>{n.name}</span>
                {n.pid && <span className="font-mono text-xs text-muted">PID {n.pid}</span>}
                {n.user && <span className="font-mono text-xs text-muted">{n.user}</span>}
                {n.role === "parent" && <span className="text-xs text-muted">parent process</span>}
                {killed && (
                  <span className="stamp ml-auto rounded border-2 border-ok px-1.5 py-0.5 font-mono text-[11px] font-medium text-ok">Terminated</span>
                )}
              </div>
              <p className={`mt-1 break-all font-mono text-xs leading-relaxed ${actor ? "text-text-2" : "text-muted"} line-clamp-3`} title={n.detail}>
                {n.detail}
              </p>
              {n.decoded && (
                <div className="mt-2.5 rounded-md border border-line-soft bg-bg px-2.5 py-2">
                  <div className="text-[11px] text-muted">Decoded payload</div>
                  <code className="mt-0.5 block break-all font-mono text-[13px] text-text">{n.decoded}</code>
                </div>
              )}

            </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
