export type Severity = "critical" | "high" | "medium" | "low" | "info" | "pass";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  detail: string;
  evidence?: string;
  remediation?: string;
};

export type PortResult = {
  port: number;
  service: string;
  state: "open" | "closed" | "filtered";
};

export type ScanReport = {
  host: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: string;
  addresses: string[];
  dnssec: boolean | null;
  tlsOk: boolean;
  httpRedirectsToHttps: boolean | null;
  serverBanner: string | null;
  headers: Record<string, string>;
  ports: PortResult[];
  findings: Finding[];
};

const TIMEOUT = 6000;

async function timedFetch(url: string, init: RequestInit = {}, ms = TIMEOUT) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "manual" });
  } finally {
    clearTimeout(t);
  }
}

export function normalizeHost(raw: string): string {
  let h = raw.trim().toLowerCase();
  h = h.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  return h;
}

async function resolveDns(host: string) {
  const addresses: string[] = [];
  let dnssec: boolean | null = null;
  for (const type of ["A", "AAAA"]) {
    try {
      const res = await timedFetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
        { headers: { accept: "application/dns-json" } },
      );
      if (!res.ok) continue;
      const json = (await res.json()) as { AD?: boolean; Answer?: { data: string; type: number }[] };
      if (typeof json.AD === "boolean") dnssec = dnssec === true ? true : json.AD;
      for (const a of json.Answer ?? []) {
        if (a.type === 1 || a.type === 28) addresses.push(a.data);
      }
    } catch {
      /* ignore */
    }
  }
  return { addresses: [...new Set(addresses)], dnssec };
}

const PORTS: { port: number; service: string }[] = [
  { port: 80, service: "HTTP" },
  { port: 443, service: "HTTPS" },
  { port: 8080, service: "HTTP alt / proxy" },
  { port: 8443, service: "HTTPS alt" },
  { port: 8000, service: "HTTP dev" },
  { port: 3000, service: "App server" },
];

async function probePorts(host: string): Promise<PortResult[]> {
  const results = await Promise.all(
    PORTS.map(async ({ port, service }) => {
      const scheme = port === 443 || port === 8443 ? "https" : "http";
      try {
        await timedFetch(`${scheme}://${host}:${port}/`, { method: "GET" }, 5000);
        return { port, service, state: "open" as const };
      } catch (e) {
        const msg = String(e);
        return {
          port,
          service,
          state: msg.includes("abort") ? ("filtered" as const) : ("closed" as const),
        };
      }
    }),
  );
  return results;
}

const HEADER_CHECKS: {
  key: string;
  title: string;
  severity: Severity;
  detail: string;
  remediation: string;
}[] = [
  {
    key: "strict-transport-security",
    title: "HSTS not enforced",
    severity: "high",
    detail:
      "No Strict-Transport-Security header. Clients can be downgraded to plaintext HTTP on the first or a hijacked connection (SSL stripping).",
    remediation: "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },
  {
    key: "content-security-policy",
    title: "No Content-Security-Policy",
    severity: "medium",
    detail:
      "Without a CSP, injected scripts from a compromised network path or XSS can exfiltrate session data.",
    remediation: "Define a CSP starting with default-src 'self' and tighten from there.",
  },
  {
    key: "x-frame-options",
    title: "Clickjacking protection missing",
    severity: "medium",
    detail: "Neither X-Frame-Options nor CSP frame-ancestors was returned.",
    remediation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
  },
  {
    key: "x-content-type-options",
    title: "MIME sniffing allowed",
    severity: "low",
    detail: "Missing X-Content-Type-Options lets browsers reinterpret response bodies.",
    remediation: "Add X-Content-Type-Options: nosniff",
  },
  {
    key: "referrer-policy",
    title: "Referrer leakage possible",
    severity: "low",
    detail: "No Referrer-Policy; full URLs may leak to third parties over the network.",
    remediation: "Add Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    key: "permissions-policy",
    title: "No Permissions-Policy",
    severity: "info",
    detail: "Powerful browser features are not explicitly restricted.",
    remediation: "Add a Permissions-Policy header disabling unused features.",
  },
];

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 18,
  medium: 10,
  low: 4,
  info: 0,
  pass: 0,
};

export async function runScan(rawHost: string): Promise<ScanReport> {
  const started = Date.now();
  const host = normalizeHost(rawHost);
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) {
    throw new Error("Enter a valid hostname, e.g. example.com");
  }

  const findings: Finding[] = [];
  const [{ addresses, dnssec }, ports] = await Promise.all([resolveDns(host), probePorts(host)]);

  let tlsOk = false;
  let headers: Record<string, string> = {};
  let serverBanner: string | null = null;
  let httpsStatus: number | null = null;

  try {
    const res = await timedFetch(`https://${host}/`, { method: "GET" });
    tlsOk = true;
    httpsStatus = res.status;
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    serverBanner = headers["server"] ?? null;
  } catch {
    tlsOk = false;
  }

  let httpRedirectsToHttps: boolean | null = null;
  try {
    const res = await timedFetch(`http://${host}/`, { method: "GET" });
    const loc = res.headers.get("location") ?? "";
    httpRedirectsToHttps = res.status >= 300 && res.status < 400 && loc.startsWith("https://");
  } catch {
    httpRedirectsToHttps = null;
  }

  // --- Transport findings
  if (!tlsOk) {
    findings.push({
      id: "tls-unreachable",
      title: "HTTPS endpoint unreachable or TLS handshake failed",
      severity: "critical",
      category: "Transport security",
      detail:
        "No valid TLS connection could be established on port 443. Traffic to this host may be unencrypted or the certificate is invalid/expired.",
      evidence: `https://${host}/ did not respond with a valid TLS session`,
      remediation: "Serve the site over TLS 1.2+ with a valid, non-expired certificate chain.",
    });
  } else {
    findings.push({
      id: "tls-ok",
      title: "Valid TLS connection established",
      severity: "pass",
      category: "Transport security",
      detail: `Encrypted channel negotiated successfully (HTTP ${httpsStatus}).`,
    });
  }

  if (httpRedirectsToHttps === false) {
    findings.push({
      id: "no-https-redirect",
      title: "Plaintext HTTP served without redirect",
      severity: "high",
      category: "Transport security",
      detail:
        "Port 80 answers without forcing an upgrade to HTTPS. Anyone on the same network path can read or modify this traffic.",
      evidence: `http://${host}/ returned a non-redirect response`,
      remediation: "301-redirect every HTTP request to the HTTPS equivalent.",
    });
  } else if (httpRedirectsToHttps === true) {
    findings.push({
      id: "https-redirect",
      title: "HTTP traffic is upgraded to HTTPS",
      severity: "pass",
      category: "Transport security",
      detail: "Port 80 issues a redirect to the encrypted endpoint.",
    });
  }

  // --- Header findings
  if (tlsOk) {
    const csp = headers["content-security-policy"] ?? "";
    for (const check of HEADER_CHECKS) {
      const present =
        !!headers[check.key] ||
        (check.key === "x-frame-options" && csp.includes("frame-ancestors"));
      if (present) {
        findings.push({
          id: `hdr-${check.key}`,
          title: `${check.key} present`,
          severity: "pass",
          category: "HTTP hardening",
          detail: "Header is configured.",
          evidence: headers[check.key] ?? "",
        });
      } else {
        findings.push({
          id: `hdr-${check.key}`,
          title: check.title,
          severity: check.severity,
          category: "HTTP hardening",
          detail: check.detail,
          remediation: check.remediation,
        });
      }
    }

    const banners = ["server", "x-powered-by", "x-aspnet-version"].filter((k) => headers[k]);
    if (banners.some((k) => /\d/.test(headers[k] ?? ""))) {
      findings.push({
        id: "banner-disclosure",
        title: "Software version disclosed in response headers",
        severity: "medium",
        category: "Information exposure",
        detail:
          "Version strings let an attacker map the host to known CVEs before ever touching it.",
        evidence: banners.map((k) => `${k}: ${headers[k] ?? ""}`).join(" | "),
        remediation: "Strip or genericise Server / X-Powered-By headers at the edge.",
      });
    }
  }

  // --- Exposure findings
  const risky = ports.filter(
    (p) => p.state === "open" && ![80, 443].includes(p.port),
  );
  if (risky.length) {
    findings.push({
      id: "extra-ports",
      title: "Non-standard service ports reachable from the internet",
      severity: "high",
      category: "Network exposure",
      detail:
        "Admin panels, dev servers and proxies on these ports are frequently unauthenticated and are a common initial-access path.",
      evidence: risky.map((p) => `${p.port}/tcp (${p.service})`).join(", "),
      remediation:
        "Firewall these ports to trusted source ranges or place them behind a VPN / zero-trust proxy.",
    });
  } else {
    findings.push({
      id: "ports-clean",
      title: "No unexpected web ports reachable",
      severity: "pass",
      category: "Network exposure",
      detail: "Only standard HTTP/HTTPS ports responded to the probe.",
    });
  }

  if (dnssec === false) {
    findings.push({
      id: "no-dnssec",
      title: "DNSSEC validation not available",
      severity: "low",
      category: "DNS integrity",
      detail:
        "Responses for this zone are not DNSSEC-signed, so cache poisoning / spoofing of the name resolution is harder to detect.",
      remediation: "Enable DNSSEC signing at your DNS provider.",
    });
  } else if (dnssec) {
    findings.push({
      id: "dnssec",
      title: "DNSSEC-signed responses",
      severity: "pass",
      category: "DNS integrity",
      detail: "Resolver reported an authenticated-data answer.",
    });
  }

  if (!addresses.length) {
    findings.push({
      id: "no-dns",
      title: "No A/AAAA records resolved",
      severity: "medium",
      category: "DNS integrity",
      detail: "The hostname did not resolve to an IP address over DNS-over-HTTPS.",
    });
  }

  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const grade =
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return {
    host,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    score,
    grade,
    addresses,
    dnssec,
    tlsOk,
    httpRedirectsToHttps,
    serverBanner,
    headers,
    ports,
    findings,
  };
}
