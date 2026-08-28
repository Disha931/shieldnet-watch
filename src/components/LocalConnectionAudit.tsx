import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, Wifi } from "lucide-react";

type Row = { label: string; value: string; ok: boolean | null; note: string };

export function LocalConnectionAudit() {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    const out: Row[] = [];
    const secure = window.isSecureContext && location.protocol === "https:";
    out.push({
      label: "Page transport",
      value: location.protocol.replace(":", "").toUpperCase(),
      ok: secure,
      note: secure
        ? "Traffic between this browser and the server is encrypted."
        : "Plaintext transport — credentials and cookies are readable on the local network.",
    });

    const nav = navigator as Navigator & {
      connection?: { effectiveType?: string; downlink?: number; rtt?: number; saveData?: boolean };
    };
    const c = nav.connection;
    out.push({
      label: "Link quality",
      value: c?.effectiveType
        ? `${c.effectiveType} · ${c.downlink ?? "?"} Mb/s · ${c.rtt ?? "?"} ms RTT`
        : "Not exposed by this browser",
      ok: null,
      note: "High latency or throttled links can indicate an interception proxy.",
    });

    out.push({
      label: "Cookie isolation",
      value: navigator.cookieEnabled ? "Cookies enabled" : "Cookies blocked",
      ok: null,
      note: "Session cookies without Secure/HttpOnly are exposed to network sniffing.",
    });

    out.push({
      label: "Mixed content",
      value: (() => {
        const bad = [...document.querySelectorAll<HTMLElement>("[src],[href]")].filter((el) =>
          (el.getAttribute("src") || el.getAttribute("href") || "").startsWith("http://"),
        ).length;
        return bad ? `${bad} insecure sub-resource(s)` : "None detected";
      })(),
      ok: true,
      note: "Insecure sub-resources let an on-path attacker inject code.",
    });

    setRows(out);

    // WebRTC local IP leak probe
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel("probe");
      const ips = new Set<string>();
      pc.onicecandidate = (e) => {
        if (!e.candidate) {
          pc.close();
          setRows((r) => [
            ...r.filter((x) => x.label !== "WebRTC IP leak"),
            {
              label: "WebRTC IP leak",
              value: ips.size ? [...ips].join(", ") : "No host candidates exposed",
              ok: ips.size === 0,
              note: ips.size
                ? "Your internal network address is discoverable by any page you visit."
                : "Browser is masking local ICE candidates.",
            },
          ]);
          return;
        }
        const m = e.candidate.candidate.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
        if (m?.[1] && !m[1].startsWith("0.")) ips.add(m[1]);
      };
      pc.createOffer().then((o) => pc.setLocalDescription(o));
    } catch {
      /* ignore */
    }
  }, []);

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        <Wifi className="size-4 text-primary" />
        <h2 className="font-mono text-sm tracking-widest uppercase">Your connection</h2>
      </div>
      <ul className="divide-y divide-border">
        {rows.map((r) => (
          <li key={r.label} className="flex gap-3 px-4 py-3">
            {r.ok === false ? (
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
            ) : (
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
            )}
            <div className="min-w-0">
              <p className="text-sm font-medium">{r.label}</p>
              <p className="truncate font-mono text-xs text-primary">{r.value}</p>
              <p className="mt-1 text-xs text-muted-foreground">{r.note}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
