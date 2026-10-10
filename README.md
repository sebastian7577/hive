# Hive

> **One server, many isolated tenants.** A multi-tenant Xray (VLESS/REALITY) + Hysteria2 panel with a built-in reseller sub-panel, per-tenant traffic quotas, and process-level isolation.

> ⚠️ **This is the first version.** It is early and rough: features are incomplete,
> docs are thin, and there are certainly bugs we haven't found yet. Treat it as a
> starting point rather than a finished product. Issues and pull requests are welcome.

[中文说明](README.zh-CN.md)

---

## Why Hive

General-purpose panels (3x-ui, Marzban) are **single-admin** or **shared-core multi-user**: every admin/client lives inside one Xray process and one config. Hive is built for the **reseller / multi-tenant** use case: split one server into **many tenants that cannot see each other**, each with its **own panel URL, its own proxy processes, and a total traffic quota**.

- **3x-ui** — single admin; "multi-node" means managing *other* 3x-ui instances.
- **Marzban** — shared Xray core, user-centric, multi-admin (WIP).
- **Hive** — per-tenant **separate Xray/Hysteria2 processes**, each with its own panel URL (random port + path), **process-level isolation** for the proxies (systemd sandbox + non-root + narrow root helper), and a **total quota** that auto-disables the tenant.

## Features

- **Main panel** (admin): system status, VLESS (REALITY) nodes, Hysteria2 nodes, port forwarding (中转), end-user management, per-user traffic, ufw firewall card, QR / share link / Clash-YAML export.
- **Limit (multi-tenant) panel**: every tenant gets its **own panel URL** (**random port + random path**, with isolated credentials and data) served by one multi-tenant web process, and manages **its own** VLESS/Hysteria2/forward nodes and clients, with a **total traffic quota**.
- **Quota enforcement**: when a tenant hits the quota, all of its nodes are disabled automatically.
- **Master switch**: pause/resume **all** limit services with one toggle.
- **Node control**: every node (including the ones created at install) can be paused and deleted.
- **Per-tenant isolated instances**: each tenant's Xray runs as its **own process** (`limit-xray@<tenant>`, own config + own stats API) and each Hysteria2 node as its own process too — one tenant (or protocol) failing does not take the others down. The main panel's status card can also restart the main VLESS and Hysteria2 processes independently.
- **HTTPS panels**: both panels serve TLS with an auto-generated self-signed certificate; the browser shows a one-time warning.
- **Isolation first**: each tenant's proxies run as separate sandboxed processes (exposure score down to **1.9–4.0**); the tenant web process runs as a **non-root** user and performs privileged actions only through a **narrow root helper**.

## Install

One line, on a fresh **Debian/Ubuntu** VPS (as root):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh)
```

It installs Xray-core, Hysteria2, the main panel and the multi-tenant (limit) panel, then prints the `https://` URL, the random path and the generated credentials. The certificate is self-signed, so the browser will warn once — that is expected.

Update in place (keeps your nodes, users, tenants, port, path and credentials) by running the same command again, or with the shortcut it installs:

```bash
hive
```

To remove:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh) uninstall
```

## Versions

- **v1.0.0** — initial public release (previously labelled `v1.10`, renumbered).
- **v1.0.1** — current:
  - panel text clarified: a VLESS node carries **both TCP and UDP** traffic;
  - removed the unused **WebSocket / gRPC / xhttp** transports (UI + code);
  - the limit panel now judges port conflicts **per protocol**, so a VLESS (TCP) node and a Hysteria2 (UDP) node may share the same port number;
  - docs: IPv4/IPv6 behaviour, the shared base port, and versioned installs.

Install a **specific version** by appending its tag:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh) v1.0.0
```

or, once installed:

```bash
hive v1.0.0
```

Without a version it installs/updates to the latest (`main`).

## Security notes

- **Credentials are random and hashed.** The install generates a random username + password and stores only a salted **PBKDF2** hash in `/opt/xray-viewer/panel_auth.json` (0600) — never in the source. You can change the password from the panel.
- **Panels are HTTPS** (self-signed cert; `Secure` cookie + HSTS). Traffic is not sent in clear text.
- **The firewall is never reset.** The installer only *adds* rules: it always keeps the SSH port(s) it can detect (from `sshd_config` and the live session), and opens `443` plus the panel port. An explicit `--reset-firewall` is required to wipe ufw.
- **Hysteria2 is pinned and verified.** The binary is fetched from the official `apernet/hysteria` release and checked against a hard-coded SHA256.
- **Tenant isolation**: each tenant runs its own **Xray process** (`limit-xray@<tenant>`) and its own Hysteria2 processes in systemd sandboxes; the tenant web process is non-root and can only touch its own units/ports through `limit-helper`.
- **Sensitive files are not world-readable.** The main Xray config (REALITY private key, UUIDs) is `0640 root:xrayconf` and the main Hysteria2 certs `0640 root:hy2main`, so the tenant user cannot read the main node's secrets.
- **The root helper only touches tenant ports.** `limit-helper` refuses to open or redirect any port outside the tenant ranges (`21000–49999`) — the only exception is the panel's own base port, used purely as the redirect target — so it cannot touch `22`, `443` or the panel ports even if a tenant panel is compromised.
- **Randomised masquerade.** The REALITY target / cert CN / Hysteria2 SNI is picked per install from a list of popular sites (override with `HIVE_MASQ=…`), so deployments don't all share one fingerprint.

## Architecture

```
            ┌─────────────────────────── main panel (xray-viewer, root, sandboxed) ───────────────────────────┐
 browser ─► │  admin UI · manages main xray + hysteria2 + forward + users + ufw · the "limit users" card        │
            └───────────────┬───────────────────────────────────────────────────────────────┬─────────────────┘
                            │ shared data (tenants.json, flock)                             │ toggle (start/stop)
                            ▼                                                                ▼
            ┌────────────── limit panel (limit-viewer, user: limitpanel, sandboxed) ──────────────┐
 tenant ──► │  per-tenant UI (by request port + path) · writes configs                            │
 (own port) │        │                                                                             │
            └────────┼─────────────────────────────────────────────────────────────────────────────┘
                     │ privileged calls (systemctl / ufw / iptables) over a unix socket
                     ▼
            ┌──────────── limit-helper (root, narrow allowlist API) ─────────────┐
            └────────────────────────────────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
   limit-xray@<tenant>      limit-hysteria@<node>   ← one process per tenant / per hy2 node
```

**All tenant panel ports are really one shared base port.** Each tenant's **random port** is only a *virtual* entry: an iptables `REDIRECT` (in `nat/PREROUTING` + `nat/OUTPUT`) rewrites it to the single shared base port, which is the only port actually listening. So only the **base port** needs a firewall rule, and one web process serves every tenant (identified by request port + path).

## Networking (IPv4 / IPv6)

The VLESS and Hysteria2 inbounds are written with `listen: 0.0.0.0`, but Xray binds the **wildcard** address (in practice `::`), so on a host with a public IPv6 address the services are reachable over **both IPv4 and IPv6** (dual-stack); Hysteria2 (`:443`) behaves the same.

The generated **share links / QR codes / Clash-YAML use the public IPv4 address** — that is what clients get by default. To connect over IPv6, put the host's IPv6 address in the client instead.

If clients connect over IPv6, make sure the firewall allows it too (ufw with `IPV6=yes`, the default).

## Isolation at a glance

`systemd-analyze security` exposure score (lower is better):

| unit | before | Hive |
|---|---|---|
| xray (main) | 9.6 UNSAFE | **2.2 OK** |
| xray-viewer (main panel) | 9.6 | **4.0 OK** |
| limit-viewer | 7.8 EXPOSED | **3.5 OK** (non-root) |
| limit-xray@<tenant> | 7.2 | **2.2 OK** |
| hysteria node | — | **1.9 OK** |

## Requirements

- Debian/Ubuntu, root, systemd.
- Python 3 + gunicorn + flask (installed by the script).
- Xray-core and Hysteria2 (installed by the script).

## License

[MIT](LICENSE)
