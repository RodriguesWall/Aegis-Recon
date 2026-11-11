# Aegis-Recon

> Self-hosted attack-surface scanner and security dashboard, written in Go.

Aegis-Recon lets you register your own projects and services, run surface-recon
scans against them, and review findings in one place. Built as a clean,
concurrent Go codebase — a single core engine shared by a CLI and an HTTP API.

**Status:** 🚧 Work in progress — V1 in development.

---

## What it does (V1)

Register a **Project**, add **Assets** (domain, host, web-app, api), trigger a
**surface scan**, and view the **findings**.

Surface scan runs six native-Go modules concurrently:

| Module | What it checks |
|---|---|
| `dns` | A/AAAA/MX/NS/TXT/CNAME records |
| `subdomain` | Passive (crt.sh) + bounded wordlist bruteforce |
| `port` | Concurrent TCP connect scan + banner grab |
| `tls` | Certificate validity, expiry, chain, SAN, ciphers |
| `httpprobe` | Status, redirects, title, security headers |
| `fingerprint` | Technology/stack detection |

No external scan engines in V1 — pure Go standard library (`net`, `crypto/tls`,
`net/http`). Results export as JSON and SARIF.

---

## Roadmap (feature per version)

### V1 — Attack surface
- [ ] Core engine: concurrent worker pool, injectable resolver/dialer
- [ ] Six surface-recon modules
- [ ] SQLite store (WAL, single-writer)
- [ ] CLI (`aegis scan <domain>`)
- [ ] HTTP API (projects, assets, scans) — single-user
- [ ] Minimal static dashboard
- [ ] JSON + SARIF output
- [ ] Single-container Docker image

### V2 — Vulnerability & platform
- [ ] Vulnerability scan: native checks (headers, weak TLS, cookie flags, exposed files)
- [ ] `nuclei` adapter for OWASP coverage
- [ ] Dependency track / SCA (OSV.dev)
- [ ] Authentication + multi-tenant
- [ ] React SPA dashboard
- [ ] Domain-ownership verification (DNS TXT), scheduled scans

---

## Architecture (short)

```
        core (engine + scanners + store + report)
       /                                          \
  aegis (CLI)                                 aegisd (HTTP API + static UI)
```

- Mono-repo, single `go.mod`.
- Every scanner implements one `Scanner` interface; the engine fans out across
  hosts with a bounded worker pool.
- SQLite embedded (no CGO), store behind an interface (swappable later).

---

## Build & run

```bash
# build the Go binaries
make build

# scan from the CLI
./bin/aegis scan example.com

# run the API daemon
./bin/aegisd                 # http://localhost:8080  (GET /health)

# run the dashboard (dev) — in another terminal
cd web && npm install && npm run dev   # http://localhost:5173
```

Or bring up API + dashboard together with Docker:

```bash
docker compose up --build    # web on :8081, api on :8080
```

---

## Authorized use only

Aegis-Recon performs active network scanning (port scan, subdomain enumeration,
HTTP probing). **Only scan systems you own or are explicitly authorized to test.**
Unauthorized scanning may be illegal in your jurisdiction. As open-source,
self-hosted software, responsibility for how it is used lies with the operator.

---

## License

MIT — see [`LICENSE`](./LICENSE).
