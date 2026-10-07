"""Hive — limit-helper: the narrow root helper for the limit panel.

Runs as root and listens on /run/limit-helper.sock (0660 root:limitpanel). It
exposes only a small allowlist of privileged operations — start/stop a
`limit-xray` / `limit-hysteria@*` unit, allow/delete a ufw port, and rebuild the
iptables port-redirect chains — so the tenant web process never needs root.

This is the first version — see README.md.
"""

import json, os, re, socket, subprocess, threading

SOCK = "/run/limit-helper.sock"
SERVER_IP_FILE = "/opt/limit/server_ip"

UNIT_RE = re.compile(r"^limit-(xray@[A-Za-z0-9._-]+|xray|hysteria@[A-Za-z0-9._@-]+)(\.service)?$")

# Only ports that belong to tenants may be touched through the helper, and only
# in the ranges the panel hands out. Everything else (22, 443, the panel ports,
# system ports, ...) is refused even if the tenant web app is compromised.
TENANT_RANGES = ((21000, 21999), (22000, 29999), (30000, 30999), (40000, 49999))
TENANT_PANEL_RANGE = (40000, 49999)
BASE_RANGE = (50000, 60000)


def _port_owned(port, ranges):
    return any(lo <= port <= hi for lo, hi in ranges)


def _run(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return 1, "", str(e)


def _server_ip():
    try:
        return open(SERVER_IP_FILE).read().strip()
    except Exception:
        return ""


def _iptables_redir(base, ports):
    ip = _server_ip()
    _run(["iptables", "-t", "nat", "-N", "LIMITREDIR"])
    _run(["iptables", "-t", "nat", "-F", "LIMITREDIR"])
    if _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", "LIMITREDIR"])[0] != 0:
        _run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "LIMITREDIR"])
    _run(["iptables", "-t", "nat", "-N", "LIMITREDIROUT"])
    _run(["iptables", "-t", "nat", "-F", "LIMITREDIROUT"])
    if _run(["iptables", "-t", "nat", "-C", "OUTPUT", "-j", "LIMITREDIROUT"])[0] != 0:
        _run(["iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", "LIMITREDIROUT"])
    for p in ports:
        if p == base:
            continue
        _run(["iptables", "-t", "nat", "-A", "LIMITREDIR",
              "-p", "tcp", "--dport", str(p), "-j", "REDIRECT", "--to-ports", str(base)])
        if ip:
            _run(["iptables", "-t", "nat", "-A", "LIMITREDIROUT",
                  "-p", "tcp", "-d", ip, "--dport", str(p), "-j", "REDIRECT", "--to-ports", str(base)])
    return 0, "ok", ""


def handle(req):
    op = req.get("op")
    if op == "systemctl":
        action = req.get("action"); unit = req.get("unit", "")
        if action not in ("restart", "start", "stop", "enable", "disable"):
            raise ValueError("bad action")
        if not UNIT_RE.match(unit):
            raise ValueError("bad unit")
        args = ["systemctl", action]
        if action == "disable":
            args.append("--now")
        args.append(unit)
        return _run(args)
    if op == "ufw":
        action = req.get("action"); port = int(req.get("port")); proto = req.get("proto", "tcp")
        if action not in ("allow", "delete"):
            raise ValueError("bad action")
        if not (1 <= port <= 65535) or not _port_owned(port, TENANT_RANGES):
            raise ValueError("port %s not owned by a tenant" % port)
        if proto not in ("tcp", "udp"):
            raise ValueError("bad proto")
        spec = "%d/%s" % (port, proto)
        if action == "allow":
            return _run(["ufw", "allow", spec])
        return _run(["ufw", "delete", "allow", spec])
    if op == "iptables_redir":
        base = int(req.get("base"))
        ports = [int(p) for p in (req.get("ports") or [])]
        if not (1 <= base <= 65535) or not _port_owned(base, (BASE_RANGE,)):
            raise ValueError("bad base")
        for p in ports:
            if not (1 <= p <= 65535) or not _port_owned(p, (TENANT_PANEL_RANGE,)):
                raise ValueError("port %d not a tenant panel port" % p)
        return _iptables_redir(base, ports)
    raise ValueError("unknown op")


def _client(conn):
    try:
        data = b""
        while b"\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        req = json.loads(data.decode().strip() or "{}")
        try:
            rc, out, err = handle(req)
            resp = {"ok": rc == 0, "out": out, "err": err}
        except Exception as e:
            resp = {"ok": False, "err": str(e)}
    except Exception as e:
        resp = {"ok": False, "err": str(e)}
    try:
        conn.sendall((json.dumps(resp) + "\n").encode())
    except Exception:
        pass
    conn.close()


def main():
    try:
        os.unlink(SOCK)
    except Exception:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    try:
        import grp
        os.chown(SOCK, 0, grp.getgrnam("limitpanel").gr_gid)
    except Exception:
        pass
    os.chmod(SOCK, 0o660)
    s.listen(16)
    while True:
        try:
            conn, _ = s.accept()
            threading.Thread(target=_client, args=(conn,), daemon=True).start()
        except Exception:
            pass


if __name__ == "__main__":
    main()

