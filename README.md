# Hive

> **One server, many isolated tenants.** A multi-tenant Xray (VLESS/REALITY) + Hysteria2 panel with a built-in reseller sub-panel, per-tenant traffic quotas, and process-level isolation.

> ⚠️ This is the initial version. It is early and rough: features are incomplete,
> docs are thin, and there are certainly bugs we haven't found yet. Treat it as a
> starting point rather than a finished product. Issues and pull requests are welcome.

[中文说明](README.zh-CN.md)

---

## Why Hive

General-purpose panels (3x-ui, Marzban) are **single-admin** or **shared-core multi-user**: every admin/client lives inside one Xray process and one config. Hive is built for the **reseller / multi-tenant** use case: split one server into **many tenants that cannot see each other**, each with its **own isolated panel, own nodes, and a total traffic quota**.

- **3x-ui** — single admin; "multi-node" means managing *other* 3x-ui instances.
- **Marzban** — shared Xray core, user-centric, multi-admin (WIP).
- **Hive** — per-tenant **separate Xray/Hysteria2 instances**, separate web panel (own port + path), **process-level isolation** (systemd sandbox + non-root + narrow root helper), and a **total quota** that auto-disables the tenant.

## Features

- **Main panel** (admin): system status, VLESS (REALITY/TLS/WS/gRPC) nodes, Hysteria2 nodes, port forwarding (中转), end-user management, per-user traffic, ufw firewall card, QR / share link / Clash-YAML export.
- **Limit (multi-tenant) panel**: every tenant gets an **isolated panel** at its own **random port + random path**, manages **its own** VLESS/Hysteria2/forward nodes and clients, with a **total traffic quota**.
- **Quota enforcement**: when a tenant hits the quota, all of its nodes are disabled automatically.
- **Master switch**: pause/resume **all** limit services with one toggle.
- **HTTPS panels**: both panels serve TLS with an auto-generated self-signed certificate; the browser shows a one-time warning.
- **Credentials hashed**: the panel password is stored salted+hashed (PBKDF2) outside the code, and can be changed from the panel.
- **Isolation first**: separate processes, systemd hardening (exposure score down to **1.9–4.0**), the tenant web process runs as a **non-root** user and performs privileged actions only through a **narrow root helper**.

## Install

One line, on a fresh **Debian/Ubuntu** VPS (as root):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh)
```

It installs Xray-core, Hysteria2, the main panel and the multi-tenant (limit) panel, then prints the `https://` URL, the random path and the generated credentials. The certificate is self-signed, so the browser will warn once — that is expected.

Run the same command again to update in place (your nodes, users, tenants, port and path are kept). To remove:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh) uninstall
```

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
   limit-xray (nobody)      limit-hysteria@<node> (hysteria)   ← per-tenant isolated instances
```

## Isolation at a glance

`systemd-analyze security` exposure score (lower is better):

| unit | before | Hive |
|---|---|---|
| xray (main) | 9.6 UNSAFE | **2.2 OK** |
| xray-viewer (main panel) | 9.6 | **4.0 OK** |
| limit-viewer | 7.8 EXPOSED | **3.5 OK** (non-root) |
| limit-xray | 7.2 | **2.2 OK** |
| hysteria node | — | **1.9 OK** |

## Requirements

- Debian/Ubuntu, root, systemd.
- Python 3 + gunicorn + flask (installed by the script).
- Xray-core and Hysteria2 (installed by the script).

## License

[MIT](LICENSE)
