# ShieldNet Watch — Network Vulnerability & Weakness Scanner

ShieldNet Watch (codename **NetProbe**) is a passive, browser-first network scanner. Point it at any public hostname and it checks transport security, exposed service ports, DNS integrity, HTTP hardening headers and your own browser connection for common weaknesses.

> **Preview:** [shieldnet-watch.lovable.app](https://shieldnet-watch.lovable.app)  
> Built with [Lovable](https://lovable.dev) + TanStack Start.

---

## What it does

- **TLS / transport check** — verifies HTTPS is reachable and the certificate negotiates cleanly.
- **HTTP → HTTPS redirect** — confirms plaintext port 80 upgrades traffic to HTTPS.
- **Security headers** — reports missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`.
- **Information disclosure** — flags version strings leaked in `Server`, `X-Powered-By` or `X-AspNet-Version`.
- **Port exposure** — probes common web ports (`80`, `443`, `8080`, `8443`, `8000`, `3000`) for reachable services.
- **DNS integrity** — resolves A/AAAA records via DNS-over-HTTPS and reports DNSSEC validation.
- **Local connection audit** — checks whether your current page is HTTPS, estimates link quality, detects mixed content and inspects WebRTC for local-IP leakage.
- **Scan history** — keeps the last 25 scans locally so you can revisit targets, dates and A–F scores.

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Framework | [TanStack Start](https://tanstack.com/start) (React 19 + Vite 7) |
| Routing | TanStack Router (file-based) |
| Server functions | `createServerFn` from `@tanstack/react-start` |
| Styling | Tailwind CSS v4 |
| UI components | shadcn/ui |
| State & history | React Query + `localStorage` |
| Icons | Lucide React |

---

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org/) 18+ (or use [nvm](https://github.com/nvm-sh/nvm))
- [Bun](https://bun.sh) or npm — the repo uses a `bun.lock` lockfile

### 1. Clone the repository

```bash
git clone https://github.com/<your-org>/shieldnet-watch.git
cd shieldnet-watch
```

### 2. Install dependencies

```bash
bun install
# or
npm install
```

### 3. Start the dev server

```bash
bun dev
# or
npm run dev
```

The app runs at `http://localhost:8080` by default.

### 4. Build for production

```bash
bun run build
# or
npm run build
```

---

## Scan usage

1. Open the app and enter a hostname in the input, e.g. `example.com`.
2. Click **Run scan**.
3. The scanner runs server-side and returns:
   - A letter grade (**A–F**) and numeric score (**0–100**).
   - Resolved IP addresses and DNSSEC status.
   - A list of open/filtered/closed ports.
   - Findings grouped by severity: **Critical**, **High**, **Medium**, **Low**, **Info**, **Pass**.
4. Expand any finding to see evidence and a recommended fix.
5. Past scans are saved to your browser's `localStorage`; use the **Scan history** panel to re-run, delete or clear entries.

### Scoring logic

| Severity | Weight |
|----------|--------|
| Critical | 30 |
| High | 18 |
| Medium | 10 |
| Low | 4 |
| Info | 0 |
| Pass | 0 |

Score = `max(0, 100 − sum(weights))`. Grades map to standard thresholds: **A ≥ 90**, **B ≥ 75**, **C ≥ 60**, **D ≥ 40**, **F < 40**.

---

## Project structure

```text
src/
├── components/           # UI components (ScanHistory, LocalConnectionAudit, shadcn)
├── lib/
│   ├── scan.functions.ts # createServerFn wrapper for the scan
│   ├── scan.server.ts    # scanner engine + types
│   └── scan-history.ts   # localStorage-backed history hook
├── routes/
│   ├── __root.tsx        # root layout
│   └── index.tsx         # home / scanner page
├── styles.css            # Tailwind v4 theme + custom tokens
└── ...
```

---

## Security notes

- **Passive only.** ShieldNet Watch performs read-only, non-intrusive checks from the server. It does not exploit vulnerabilities, run brute-force attacks, or modify the target.
- **Authorised targets only.** Only scan hosts you own or have explicit permission to test. Scanning third-party systems without authorisation may violate local laws and acceptable-use policies.
- **External reconnaissance.** The scanner queries public DNS resolvers (Cloudflare DNS-over-HTTPS) and makes outbound HTTP/HTTPS probes. These requests originate from the hosting infrastructure, not your browser.
- **No stored scan data.** Scan results are returned to your browser and optionally cached in `localStorage` on your device. No scan data is persisted on the server or in a backend database.
- **Local connection audit is client-side.** The WebRTC and mixed-content checks run entirely in your browser and do not leave the page.
- **Edge runtime.** Server functions run in a serverless Worker environment. Do not add Node-only packages that spawn child processes or depend on native binaries (e.g. `sharp`, `puppeteer`, `nmap`).

---

## Deployment

ShieldNet Watch is published through Lovable. You can also deploy the built output anywhere that supports the TanStack Start / Vite production bundle.

Stable URLs:

- **Production:** `https://shieldnet-watch.lovable.app`
- **Preview:** `https://id-preview--12a4695c-afa3-4220-99d4-5102f414ea01.lovable.app`

To connect this repo to your own GitHub account, open the **Plus (+) menu → GitHub → Connect project** in the Lovable editor.

---

## License

This project was generated with [Lovable](https://lovable.dev) and is provided as-is for your own use and modification. Refer to your Lovable workspace terms for ownership details.

---

## Acknowledgements

- [TanStack](https://tanstack.com) for Start, Router and Query.
- [shadcn/ui](https://ui.shadcn.com) for the component primitives.
- [Lucide](https://lucide.dev) for the icon set.
- Cloudflare for public DNS-over-HTTPS endpoints used during resolution.
