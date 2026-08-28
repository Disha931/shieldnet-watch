import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  Fingerprint,
  Globe,
  Lock,
  Radar,
  Server,
  TerminalSquare,
} from "lucide-react";

import { scanNetwork } from "@/lib/scan.functions";
import type { Finding, ScanReport, Severity } from "@/lib/scan.server";
import { useScanHistory } from "@/lib/scan-history";
import { LocalConnectionAudit } from "@/components/LocalConnectionAudit";
import { ScanHistory } from "@/components/ScanHistory";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";


export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NetProbe — Network Vulnerability & Weakness Scanner" },
      {
        name: "description",
        content:
          "Scan any host for network weaknesses: TLS transport, exposed ports, DNS integrity, HTTP hardening headers and your own connection's leaks.",
      },
      { property: "og:title", content: "NetProbe — Network Vulnerability Scanner" },
      {
        property: "og:description",
        content:
          "Live checks for TLS, open ports, DNSSEC, security headers and local connection leaks.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const SEV_STYLE: Record<Severity, { chip: string; label: string }> = {
  critical: { chip: "bg-sev-critical/15 text-sev-critical border-sev-critical/40", label: "CRITICAL" },
  high: { chip: "bg-sev-high/15 text-sev-high border-sev-high/40", label: "HIGH" },
  medium: { chip: "bg-sev-medium/15 text-sev-medium border-sev-medium/40", label: "MEDIUM" },
  low: { chip: "bg-sev-low/15 text-sev-low border-sev-low/40", label: "LOW" },
  info: { chip: "bg-sev-info/15 text-sev-info border-sev-info/40", label: "INFO" },
  pass: { chip: "bg-sev-pass/15 text-sev-pass border-sev-pass/40", label: "PASS" },
};

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "pass"];

function FindingCard({ f }: { f: Finding }) {
  const s = SEV_STYLE[f.severity];
  return (
    <li className="rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-2 py-0.5 font-mono text-[10px] tracking-widest ${s.chip}`}>
          {s.label}
        </span>
        <span className="font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
          {f.category}
        </span>
      </div>
      <h3 className="mt-2 font-medium">{f.title}</h3>
      <p className="mt-1 text-sm text-muted-foreground">{f.detail}</p>
      {f.evidence ? (
        <pre className="mt-3 overflow-x-auto rounded border border-border bg-background px-3 py-2 font-mono text-xs text-accent">
          {f.evidence}
        </pre>
      ) : null}
      {f.remediation ? (
        <p className="mt-3 border-l-2 border-primary/60 pl-3 text-xs text-foreground/80">
          <span className="font-mono tracking-wider text-primary uppercase">Fix · </span>
          {f.remediation}
        </p>
      ) : null}
    </li>
  );
}

function Report({ r }: { r: ScanReport }) {
  const counts = ORDER.map((s) => ({ s, n: r.findings.filter((f) => f.severity === s).length }));
  const sorted = [...r.findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

  return (
    <div className="mt-10 space-y-6">
      <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
        <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-card px-8 py-6">
          <span className="font-mono text-6xl leading-none font-bold text-primary">{r.grade}</span>
          <span className="mt-2 font-mono text-xs tracking-widest text-muted-foreground">
            {r.score}/100
          </span>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="font-mono text-sm text-accent">{r.host}</p>
          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
            <Meta icon={Globe} k="Resolved" v={r.addresses.join(", ") || "—"} />
            <Meta icon={Lock} k="TLS" v={r.tlsOk ? "Established" : "Failed"} />
            <Meta icon={Fingerprint} k="DNSSEC" v={r.dnssec === null ? "Unknown" : r.dnssec ? "Signed" : "Unsigned"} />
            <Meta icon={Server} k="Banner" v={r.serverBanner ?? "Hidden"} />
            <Meta
              icon={Activity}
              k="HTTP→HTTPS"
              v={r.httpRedirectsToHttps === null ? "No response" : r.httpRedirectsToHttps ? "Enforced" : "Missing"}
            />
            <Meta icon={Radar} k="Duration" v={`${r.durationMs} ms`} />
          </dl>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {counts.map(({ s, n }) => (
          <span
            key={s}
            className={`rounded border px-3 py-1 font-mono text-xs ${SEV_STYLE[s].chip} ${n ? "" : "opacity-40"}`}
          >
            {SEV_STYLE[s].label} {n}
          </span>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border px-4 py-3 font-mono text-sm tracking-widest uppercase">
          Port exposure
        </div>
        <div className="grid grid-cols-2 gap-px bg-border sm:grid-cols-3 lg:grid-cols-6">
          {r.ports.map((p) => (
            <div key={p.port} className="bg-card px-4 py-3">
              <p className="font-mono text-sm">
                <span className={p.state === "open" ? "text-primary" : "text-muted-foreground"}>
                  {p.port}/tcp
                </span>
              </p>
              <p className="text-xs text-muted-foreground">{p.service}</p>
              <p
                className={`mt-1 font-mono text-[10px] tracking-widest uppercase ${
                  p.state === "open" ? "text-sev-high" : "text-muted-foreground"
                }`}
              >
                {p.state}
              </p>
            </div>
          ))}
        </div>
      </div>

      <ul className="space-y-3">
        {sorted.map((f) => (
          <FindingCard key={f.id} f={f} />
        ))}
      </ul>
    </div>
  );
}

function Meta({
  icon: Icon,
  k,
  v,
}: {
  icon: typeof Globe;
  k: string;
  v: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
        <Icon className="size-3" /> {k}
      </dt>
      <dd className="truncate font-mono text-xs text-foreground">{v}</dd>
    </div>
  );
}

function Index() {
  const [host, setHost] = useState("");
  const scan = useServerFn(scanNetwork);
  const history = useScanHistory();
  const mutation = useMutation({
    mutationFn: (h: string) => scan({ data: { host: h } }),
    onSuccess: (report) => history.record(report as ScanReport),
  });

  const runScan = (h: string) => {
    const trimmed = h.trim();
    if (!trimmed) return;
    setHost(trimmed);
    mutation.mutate(trimmed);
  };


  return (
    <main className="min-h-screen px-4 py-12">
      <div className="mx-auto max-w-4xl">
        <header className="text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 font-mono text-[10px] tracking-widest text-primary uppercase">
            <TerminalSquare className="size-3" /> Passive network assessment
          </div>
          <h1 className="mt-5 text-4xl font-bold tracking-tight sm:text-5xl">
            Network Vulnerability Scanner
          </h1>
          <p className="mx-auto mt-3 max-w-xl text-sm text-muted-foreground">
            Probe any host for transport weaknesses, exposed service ports, DNS integrity gaps and
            missing hardening controls — then audit the connection you are sitting on right now.
          </p>
        </header>

        <form
          className="mt-8 flex flex-col gap-3 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            runScan(host);
          }}

        >
          <Input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="example.com"
            aria-label="Hostname to scan"
            className="h-12 font-mono"
          />
          <Button type="submit" size="lg" className="h-12 px-8" disabled={mutation.isPending}>
            <Radar className={mutation.isPending ? "animate-spin" : ""} />
            {mutation.isPending ? "Scanning" : "Run scan"}
          </Button>
        </form>

        <p className="mt-2 text-xs text-muted-foreground">
          Only scan hosts you own or are authorised to test.
        </p>

        {mutation.isPending ? (
          <div className="scanline mt-10 h-28 rounded-lg border border-border bg-card p-4 font-mono text-xs text-primary">
            <p>&gt; resolving DNS records…</p>
            <p>&gt; negotiating TLS…</p>
            <p>&gt; probing service ports…</p>
          </div>
        ) : null}

        {mutation.isError ? (
          <div className="mt-8 flex items-start gap-3 rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
            <p>{(mutation.error as Error).message}</p>
          </div>
        ) : null}

        {mutation.data ? <Report r={mutation.data as ScanReport} /> : null}

        <div className="mt-10">
          <ScanHistory
            entries={history.entries}
            onRerun={runScan}
            onRemove={history.remove}
            onClear={history.clear}
          />
        </div>

        <div className="mt-10">
          <LocalConnectionAudit />
        </div>

      </div>
    </main>
  );
}
