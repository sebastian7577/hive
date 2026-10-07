"""Hive — main (admin) panel.

A single Flask app (served by gunicorn over HTTPS) that manages the main
Xray (VLESS/REALITY) and Hysteria2 instances, port-forwarding rules, end
users, the ufw firewall, and the multi-tenant "limit" sub-panel.

Runtime state lives under /usr/local/etc/xray/ (configs, users, hy2 nodes,
fwd rules, traffic totals) and /opt/xray-viewer/ (url_prefix, server_ip,
secret_key, panel_auth.json, tls.crt/tls.key).

This is the first version — see README.md.
"""

import json, os, functools, datetime, subprocess, uuid, shutil, secrets, sys, threading, time, re, hashlib, hmac, socket
from urllib.parse import quote
sys.path.insert(0, os.path.dirname(__file__))
from flask import Flask, Blueprint, request, session, redirect, url_for, render_template_string, jsonify
import traffic_store


def atomic_write_json(path, data, keep=5, chmod=None):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    if os.path.exists(path):
        try:
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S%f")
            bak = path + ".bak." + ts
            shutil.copy2(path, bak)
        except Exception:
            pass
        try:
            baks = sorted(
                p for p in os.listdir(os.path.dirname(path))
                if p.startswith(os.path.basename(path) + ".bak.")
            )
            for old in baks[:-keep]:
                try:
                    os.unlink(os.path.join(os.path.dirname(path), old))
                except Exception:
                    pass
        except Exception:
            pass
    os.replace(tmp_path, path)
    if chmod is not None:
        try:
            os.chmod(path, chmod)
        except Exception:
            pass

app = Flask(__name__)

SECRET_KEY_FILE = "/opt/xray-viewer/secret_key"
ALLOWLIST_HINT_FILE = "/opt/xray-viewer/.allowlist_hint_done"
def _load_secret_key():
    try:
        with open(SECRET_KEY_FILE) as f:
            s = f.read().strip()
        if len(s) >= 32:
            return s
    except Exception:
        pass
    s = secrets.token_hex(32)
    try:
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, s.encode())
        os.close(fd)
    except Exception:
        pass
    return s

app.secret_key = _load_secret_key()
TLS_CRT_FILE = "/opt/xray-viewer/tls.crt"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="admin_sess",
                  SESSION_COOKIE_SECURE=os.path.exists(TLS_CRT_FILE),
                  PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=1))

@app.after_request
def _security_headers(resp):
    if os.path.exists(TLS_CRT_FILE):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

PANEL_PREFIX_FILE = "/opt/xray-viewer/url_prefix"
SERVER_IP_FILE = "/opt/xray-viewer/server_ip"

def _load_panel_prefix():
    try:
        with open(PANEL_PREFIX_FILE) as f:
            p = f.read().strip()
        if p.startswith("/") and len(p) > 1:
            return p
    except Exception:
        pass
    return "/xK2u"

PANEL_PREFIX = _load_panel_prefix()

def _server_addr():
    try:
        with open(SERVER_IP_FILE) as f:
            v = f.read().strip()
        if v and not v.lower().startswith(("http", "/")):
            return v
    except Exception:
        pass
    return "127.0.0.1"

panel = Blueprint("panel", __name__, url_prefix=PANEL_PREFIX)

USERNAME = "admin"
PASSWORD = "admin"
AUTH_FILE = "/opt/xray-viewer/panel_auth.json"

# Panel credentials are stored salted+hashed in panel_auth.json (0600), never in
# the source. _auth() re-reads the file on every login so a password change takes
# effect immediately.
def _hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000)
    return "pbkdf2_sha256$200000$%s$%s" % (salt, dk.hex())

def _verify_pw(pw, stored):
    try:
        _algo, iters, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), h)
    except Exception:
        return False

def _auth():
    try:
        d = json.load(open(AUTH_FILE))
        u = d.get("username"); h = d.get("password_hash")
        if u and h:
            return u, h
    except Exception:
        pass
    return USERNAME, _hash_pw(PASSWORD)

def _save_auth(username, password_hash):
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"username": username, "password_hash": password_hash}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)

CONFIG_PATH = "/usr/local/etc/xray/config.json"
DISABLED_PATH = "/usr/local/etc/xray/disabled_clients.json"
DISABLED_INBOUNDS_PATH = "/usr/local/etc/xray/disabled_inbounds.json"
USERS_PATH = "/usr/local/etc/xray/users.json"
HY2_NODES_PATH = "/usr/local/etc/xray/hy2_nodes.json"
HY2_CONF_DIR = "/etc/hysteria/conf.d"
HY2_UNIT_PATH = "/etc/systemd/system/hysteria-node@.service"
HY2_UNIT_NAME = "hysteria-node@{id}.service"
XRAY_SERVICE_NAME = "xray"
DEFAULT_FLOW = "xtls-rprx-vision"
TLS_CERT_FILE = "/etc/hysteria/server.crt"
TLS_KEY_FILE = "/etc/hysteria/server.key"
PROTECTED_PORTS = {10085}
PROTECTED_HY2_IDS = set()
ADMIN_USERS = {"admin"}
VLESS_PROTOCOLS = {"vless"}
HY2_STATS_HOST = "127.0.0.1"
FWD_RULES_PATH = "/usr/local/etc/xray/fwd.json"
PROTECTED_FWD_IDS = set()

EXCLUDED_PROTOCOLS = {"dokodemo-door"}

LIMIT_DATA_DIR = "/opt/limit/data"
LIMIT_TENANTS_PATH = LIMIT_DATA_DIR + "/tenants.json"
LIMIT_LOCK_PATH = LIMIT_DATA_DIR + "/.tenants.lock"
LIMIT_PAUSED_FILE = "/opt/limit/.paused"

def _limit_update(mutator):
    import fcntl
    try:
        os.makedirs(LIMIT_DATA_DIR, exist_ok=True)
        lk = open(LIMIT_LOCK_PATH, "w")
    except Exception as e:
        return False, str(e)
    try:
        fcntl.flock(lk, fcntl.LOCK_EX)
        ts = _limit_load()
        res = mutator(ts)
        tmp = LIMIT_TENANTS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"tenants": ts}, f, indent=2, ensure_ascii=False)
        try:
            os.chmod(tmp, 0o660)
        except Exception:
            pass
        os.replace(tmp, LIMIT_TENANTS_PATH)
        return True, res
    except Exception as e:
        return False, str(e)
    finally:
        try:
            fcntl.flock(lk, fcntl.LOCK_UN); lk.close()
        except Exception:
            pass

def _limit_load():
    try:
        with open(LIMIT_TENANTS_PATH) as f:
            d = json.load(f)
        ts = d.get("tenants", []) if isinstance(d, dict) else d
        return ts if isinstance(ts, list) else []
    except Exception:
        return []

def _limit_save(ts):
    try:
        os.makedirs(LIMIT_DATA_DIR, exist_ok=True)
        tmp = LIMIT_TENANTS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"tenants": ts}, f, indent=2, ensure_ascii=False)
        os.replace(tmp, LIMIT_TENANTS_PATH)
        return True
    except Exception:
        return False

def _gen_pw(n=12):
    U = "ABCDEFGHJKLMNPQRSTUVWXYZ"; L = "abcdefghijkmnpqrstuvwxyz"
    D = "23456789"; S = "!@%^*_-=+."; A = U + L + D + S
    s = secrets.choice(U) + secrets.choice(L) + secrets.choice(D) + secrets.choice(S)
    while len(s) < n:
        s += secrets.choice(A)
    s = list(s)
    for i in range(len(s) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        s[i], s[j] = s[j], s[i]
    return "".join(s)

def _limit_panel_port():
    try:
        with open("/opt/limit/panel_port") as f:
            return f.read().strip()
    except Exception:
        pass
    try:
        m = re.search(r"-b 0\.0\.0\.0:(\d+)", open("/etc/systemd/system/limit-viewer.service").read())
        return m.group(1) if m else ""
    except Exception:
        return ""

def _alloc_panel_port(ts, base_port):
    used = {int(t.get("panel_port", 0)) for t in ts if t.get("panel_port")}
    for _ in range(300):
        p = secrets.randbelow(10000) + 40000
        if p == int(base_port or 0) or p in used:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", p))
        except Exception:
            p = 0
        finally:
            s.close()
        if p:
            return p
    return 0

def _limit_view():
    out = []
    ip = _server_addr()
    for t in _limit_load():
        used = int(t.get("used_up", 0)) + int(t.get("used_down", 0))
        q = int(t.get("quota_bytes", 0) or 0)
        pp = t.get("panel_port", "")
        out.append({"id": t.get("id", ""), "name": t.get("name", ""), "path": t.get("path", ""),
                    "user": t.get("user", ""), "pass": t.get("pass", ""), "port": pp,
                    "addr": ("https://%s:%s/%s/login" % (ip, pp, t.get("path", ""))) if pp else "",
                    "exhausted": bool(t.get("exhausted")),
                    "used_h": human_bytes(used), "quota_h": human_bytes(q),
                    "pct": (min(100, int(used * 100 / q)) if q else 0)})
    return out

_limit_state_cache = {"t": 0.0, "on": False}

def _limit_hy2_units():
    """当前已加载的 limit-hysteria@*.service 实例名列表。"""
    try:
        r = subprocess.run(["systemctl", "list-units", "--all", "--type=service",
                            "--no-legend", "--plain", "limit-hysteria@*"],
                           capture_output=True, text=True, timeout=10)
        out = []
        for line in (r.stdout or "").splitlines():
            u = line.split()[0].strip() if line.split() else ""
            if u.startswith("limit-hysteria@") and u.endswith(".service"):
                out.append(u)
        return out
    except Exception:
        return []

def _limit_on():
    """limit 总开关是否开启：存在暂停标记则关闭；否则以 limit-viewer 是否运行判定。
    结果缓存 5 秒，避免每次渲染都调用 systemctl。"""
    now = time.time()
    if now - _limit_state_cache["t"] < 5:
        return _limit_state_cache["on"]
    on = False
    try:
        if not os.path.exists(LIMIT_PAUSED_FILE):
            r = subprocess.run(["systemctl", "is-active", "limit-viewer"],
                               capture_output=True, text=True, timeout=8)
            on = (r.stdout or "").strip() == "active"
    except Exception:
        on = False
    _limit_state_cache.update(t=now, on=on)
    return on

LOGIN_LOCK_PATH = "/usr/local/etc/xray/login_lock.json"
LOGIN_LOCK_FAIL_LIMIT = 3
LOGIN_LOCK_SECONDS = 6 * 3600

BASE_CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  background: #f0f2f5;
  color: #1f2329;
  margin: 0;
}
a { color: #2f6fed; text-decoration: none; }
.topbar {
  background: #fff;
  border-bottom: 1px solid #e5e8ec;
  padding: 14px 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.topbar .brand {
  font-size: 16px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
}
.brand .logo {
  width: 26px; height: 26px;
  border-radius: 6px;
  background: linear-gradient(135deg,#2f6fed,#5b8def);
  display: inline-block;
}
.logout-link { font-size: 13px; color: #8a929e; }
.logout-link:hover { color: #2f6fed; }

.wrap { max-width: 1080px; margin: 24px auto; padding: 0 20px 40px; }

.panel {
  background: #fff; border-radius: 10px; border: 1px solid #eceff2;
  margin-bottom: 20px; overflow: hidden;
}
.panel-head {
  padding: 14px 20px; border-bottom: 1px solid #eceff2;
  font-size: 14px; font-weight: 600; color: #1f2329;
  display: flex; align-items: center; justify-content: space-between;
  gap: 8px; flex-wrap: wrap;
}
.panel-head .count {
  font-size: 12px; font-weight: 500; color: #2f6fed;
  background: #eaf1fe; padding: 2px 9px; border-radius: 10px;
}
.btn-sm {
  font-size: 12.5px; padding: 6px 14px; border-radius: 6px;
  background: #2f6fed; color: #fff; border: none; cursor: pointer; font-weight: 500;
}
.btn-sm:hover { background: #2760d6; }
.btn-sm-warn {
  font-size: 12px; padding: 5px 10px; border-radius: 6px;
  background: #fff3e0; color: #c67c00; border: 1px solid #f6dfb8; cursor: pointer; font-weight: 500;
}
.btn-sm-warn:hover { background: #fbe6c4; }
.btn-sm-resume {
  font-size: 12px; padding: 5px 10px; border-radius: 6px;
  background: #e8f7ee; color: #1a9d55; border: 1px solid #c8ecd6; cursor: pointer; font-weight: 500;
}
.btn-sm-resume:hover { background: #d3f0de; }
.btn-sm-danger {
  font-size: 12px; padding: 5px 10px; border-radius: 6px;
  background: #fdecec; color: #d9414a; border: 1px solid #f7cfd2; cursor: pointer; font-weight: 500;
}
.btn-sm-danger:hover { background: #fbdadb; }
.btn-sm-reset {
  font-size: 12px; padding: 5px 10px; border-radius: 6px;
  background: #eef1f5; color: #4a5361; border: 1px solid #dde2e8; cursor: pointer; font-weight: 500;
}
.btn-sm-reset:hover { background: #e2e6eb; }
.row-actions { display: flex; gap: 6px; flex-wrap: wrap; }

table { width: 100%; border-collapse: collapse; }
th {
  text-align: left; font-size: 12px; color: #8a929e; font-weight: 500;
  padding: 10px 20px; background: #fafbfc; border-bottom: 1px solid #eceff2;
}
td {
  padding: 12px 20px; font-size: 13px; border-bottom: 1px solid #f2f4f6;
  color: #1f2329;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafbfc; }
tr.paused td { opacity: 0.55; }

.mono { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12.5px; color: #4a5361; }
.tag {
  display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 4px;
  background: #eaf1fe; color: #2f6fed; font-weight: 500; margin: 2px 3px 2px 0;
}
.tag.status-run { background: #e8f7ee; color: #1a9d55; }
.tag.status-pause { background: #fdecec; color: #d9414a; }
.tag-vless { background: #eaf1fe; color: #2f6fed; }
.tag-hy2 { background: #f6ecfe; color: #8b3dd4; }
.node-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.node-chip {
  display: inline-flex; align-items: center; gap: 4px;
  background: #f3f5f7; border: 1px solid #e4e8ec; border-radius: 999px;
  padding: 2px 8px; font-size: 11.5px; color: #3c434c; white-space: nowrap;
}
.node-chip.chip-protected { background: #fdf6e3; border-color: #f1e2b6; color: #9a7b1f; }
.chip-x {
  border: 0; background: transparent; color: #98a1ab; cursor: pointer;
  font-size: 13px; line-height: 1; padding: 0 1px;
}
.chip-x:hover:not(:disabled) { color: #d9414a; }
.chip-x:disabled { color: #c8cdd3; cursor: not-allowed; }
.modal-sub-label { font-size: 12px; color: #8a929e; margin-bottom: 6px; }
.badge-flow { font-size: 11px; color: #6b7280; }
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 14px; }
.form-grid .full { grid-column: 1 / -1; }
.form-grid label { font-size: 12px; color: #8a929e; display: block; margin-bottom: 4px; }
.form-grid input, .form-grid select {
  width: 100%; padding: 7px 10px; font-size: 13px;
  border: 1px solid #dfe3e8; border-radius: 6px; background: #fff; color: #1f2329;
}
.form-grid input:focus, .form-grid select:focus { outline: none; border-color: #2f6fed; }
.form-grid .hint { font-size: 11px; color: #b0b6bd; margin-top: 3px; }
.hidden { display: none !important; }
pre.raw-json { white-space: pre-wrap; word-break: break-all; }
.traffic-up { color: #1a9d55; font-size: 12px; }
.traffic-down { color: #2f6fed; font-size: 12px; }

.kv-grid { display: grid; grid-template-columns: 1fr 1fr; }
.kv-grid .kv { padding: 12px 20px; border-bottom: 1px solid #f2f4f6; font-size: 13px; }
.kv .k { color: #8a929e; font-size: 12px; margin-bottom: 3px; }
.kv .v { color: #1f2329; font-weight: 500; }

.footer-note { text-align: center; font-size: 12px; color: #b0b6bd; margin-top: 8px; }

.login-shell {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #f0f2f5;
}
.login-card {
  background: #fff; border-radius: 12px; padding: 36px 32px;
  width: 320px; border: 1px solid #eceff2;
  box-shadow: 0 4px 24px rgba(20,30,50,0.06);
}
.login-card .logo { width: 40px; height: 40px; border-radius: 9px;
  background: linear-gradient(135deg,#2f6fed,#5b8def); margin: 0 auto 14px; }
.login-card h2 { text-align: center; font-size: 17px; margin: 0 0 22px; color: #1f2329; }
.field-label { font-size: 12px; color: #8a929e; margin-bottom: 6px; display: block; }
.field { margin-bottom: 16px; }
input[type=text], input[type=password] {
  width: 100%; padding: 9px 12px; font-size: 14px;
  border: 1px solid #dfe3e8; border-radius: 7px; background: #fff; color: #1f2329;
}
input[type=text]:focus, input[type=password]:focus {
  outline: none; border-color: #2f6fed; box-shadow: 0 0 0 3px rgba(47,111,237,0.12);
}
.btn-primary {
  width: 100%; padding: 10px; border: none; border-radius: 7px;
  background: #2f6fed; color: #fff; font-size: 14px; font-weight: 500; cursor: pointer;
  margin-top: 4px;
}
.btn-primary:hover { background: #2760d6; }
.login-err {
  background: #fdecec; color: #d9414a; font-size: 12.5px;
  padding: 8px 12px; border-radius: 6px; margin-bottom: 16px; text-align: center;
}
.empty-state { padding: 32px 20px; text-align: center; color: #8a929e; font-size: 13px; }
.flash-msg {
  padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 16px;
  line-height: 1.7;
}
.flash-msg.ok { background: #e8f7ee; color: #1a9d55; }
.flash-msg.err { background: #fdecec; color: #d9414a; }
.flash-msg .mono { color: inherit; }
#async-toast {
  position: fixed; bottom: 28px; left: 50%; transform: translateX(-50%);
  max-width: 640px; padding: 12px 18px; border-radius: 8px; font-size: 13px;
  line-height: 1.6; color: #1a9d55; background: #e8f7ee;
  box-shadow: 0 6px 24px rgba(0,0,0,0.15); display: none; z-index: 90;
}
#async-toast.show { display: block; }
#async-toast.err { color: #d9414a; background: #fdecec; }
#async-toast .mono { color: inherit; }
form.async-form.busy button { opacity: 0.5; pointer-events: none; }

.modal-backdrop {
  display: none; position: fixed; inset: 0; background: rgba(20,25,35,0.35);
  align-items: center; justify-content: center; z-index: 50;
}
.modal-backdrop.open { display: flex; }
.modal-box {
  background: #fff; border-radius: 12px; padding: 24px 26px; width: 360px;
  box-shadow: 0 8px 32px rgba(20,30,50,0.18);
}
.modal-box h3 { margin: 0 0 16px; font-size: 15px; color: #1f2329; }
.an-sec-head { font-size: 12px; color: #8a929e; font-weight: 600; margin-bottom: 8px; }
.node-check-list { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; max-height: 260px; overflow-y: auto; }
.node-check-item {
  display: flex; align-items: center; gap: 10px; font-size: 13px;
  padding: 8px 10px; border: 1px solid #eceff2; border-radius: 7px;
}
.node-check-item input { width: 15px; height: 15px; }
.an-bound-item {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  font-size: 13px; padding: 8px 10px; border: 1px solid #eceff2; border-radius: 7px;
}
.an-bound-item .lbl { display: flex; align-items: center; gap: 8px; min-width: 0; }
.an-empty { font-size: 12px; color: #8a929e; padding: 6px 2px; }
.unbind-btn {
  font-size: 12px; padding: 3px 10px; border-radius: 5px; flex-shrink: 0; cursor: pointer;
  background: #fdecec; color: #d33; border: 1px solid #f5c6c6; font-weight: 500;
}
.unbind-btn:disabled { background: #f5f6f7; color: #b9bfc7; border-color: #e4e6e8; cursor: not-allowed; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; }
.btn-cancel {
  font-size: 13px; padding: 8px 16px; border-radius: 6px;
  background: #f1f2f4; color: #4a5361; border: none; cursor: pointer; font-weight: 500;
}
.btn-cancel:hover { background: #e2e6eb; }

.sv-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px 24px; padding: 20px; }
.sv-grid-lines { grid-template-columns: 1fr 1fr 1fr 1fr; padding: 0; }
.sv-grid-lines .kv { padding: 14px 20px; border-bottom: 1px solid #f2f4f6; border-right: 1px solid #f2f4f6; margin: 0; }
.sv-grid-lines .kv:nth-child(4n) { border-right: none; }
.sv-grid-lines .kv:nth-last-child(-n+4) { border-bottom: none; }
.sv-gauge-cell { text-align: center; }
.gauge {
  --p: 0; --c: #67C23A;
  width: 108px; height: 108px; border-radius: 50%;
  background: conic-gradient(var(--c) calc(var(--p) * 1%), #eef1f5 0);
  display: flex; align-items: center; justify-content: center;
  margin: 4px auto 12px; position: relative;
}
.gauge::before { content: ""; position: absolute; inset: 10px; background: #fff; border-radius: 50%; }
.gauge span { position: relative; z-index: 1; font-size: 16px; font-weight: 600; color: #1f2329; }
.gauge-label { font-size: 13px; color: #4a5361; }
.gauge-label b { color: #1f2329; font-weight: 600; }
.stat-inline { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
.k .note { color: #b0b6bd; font-size: 11px; font-weight: 400; margin-left: 4px; }
@media (max-width: 760px) {
  .sv-grid { grid-template-columns: repeat(2, 1fr); }
  .sv-grid-lines { grid-template-columns: 1fr 1fr; }
}

/* ===== Dark theme ===== */
.theme-btn {
  font-size: 13px; padding: 5px 10px; border-radius: 6px;
  background: #eef1f5; color: #4a5361; border: 1px solid #dde2e8;
  cursor: pointer; font-weight: 500; line-height: 1.4;
}
.theme-btn:hover { background: #e2e6eb; }
html.dark body { background: #111417; color: #e6e9ee; }
html.dark a { color: #6ea8ff; }
html.dark .topbar { background: #1a1e24; border-bottom: 1px solid #2a2f37; }
html.dark .brand .logo { filter: brightness(1.1); }
html.dark .logout-link { color: #8b93a0; }
html.dark .logout-link:hover { color: #6ea8ff; }
html.dark .panel { background: #1a1e24; border: 1px solid #2a2f37; }
html.dark .panel-head { border-bottom: 1px solid #2a2f37; color: #e6e9ee; }
html.dark .panel-head .count { background: #23314a; color: #7faeff; }
html.dark .btn-sm { background: #2f6fed; }
html.dark .btn-sm:hover { background: #2760d6; }
html.dark .btn-sm-warn { background: #3a3020; color: #e3b36a; border-color: #4d4028; }
html.dark .btn-sm-resume { background: #1e3328; color: #5fd08c; border-color: #2c4a39; }
html.dark .btn-sm-danger { background: #382126; color: #ef7d84; border-color: #503036; }
html.dark .btn-sm-reset { background: #23272e; color: #b9c0ca; border-color: #343a44; }
html.dark th {
  background: #171a1f; color: #8b93a0; border-bottom: 1px solid #2a2f37;
}
html.dark td { color: #e6e9ee; border-bottom: 1px solid #24282f; }
html.dark tr:hover td { background: #1f242b; }
html.dark .mono { color: #9aa3af; }
html.dark .tag { background: #23314a; color: #7faeff; }
html.dark .tag.status-run { background: #1e3328; color: #5fd08c; }
html.dark .tag.status-pause { background: #382126; color: #ef7d84; }
html.dark .tag-vless { background: #23314a; color: #7faeff; }
html.dark .tag-hy2 { background: #2c2440; color: #c08af0; }
html.dark .node-chip { background: #20252c; border-color: #2e343d; color: #cdd4dd; }
html.dark .node-chip.chip-protected { background: #332c19; border-color: #50421e; color: #d6b85a; }
html.dark .chip-x { color: #78818d; }
html.dark .modal-sub-label { color: #8b93a0; }
html.dark .badge-flow { color: #8b93a0; }
html.dark .form-grid label { color: #8b93a0; }
html.dark .form-grid input, html.dark .form-grid select {
  border-color: #343a44; background: #20252c; color: #e6e9ee;
}
html.dark .theme-btn { background: #23272e; color: #b9c0ca; border-color: #343a44; }
html.dark .theme-btn:hover { background: #2c313a; }
html.dark .empty-state { color: #8b93a0; }
html.dark .gauge::before { background: #1a1e24; }
html.dark .gauge span { color: #e6e9ee; }
html.dark .gauge-label { color: #9aa3af; }
html.dark .gauge-label b { color: #e6e9ee; }
html.dark .k .note { color: #7a828d; }
"""

LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<title>admin</title>
<style>""" + BASE_CSS + r"""</style></head>
<body>
<div class="login-shell">
  <div class="login-card">
    <div class="logo"></div>
    <h2>admin 登录</h2>
    {% if error %}<div class="login-err">{{ error }}</div>{% endif %}
    <form method="post">
      <div class="field">
        <label class="field-label">用户名</label>
        <input type="text" name="username" autocomplete="off">
      </div>
      <div class="field">
        <label class="field-label">密码</label>
        <input type="password" name="password">
      </div>
      <button class="btn-primary" type="submit">登 录</button>
    </form>
  </div>
</div>
</body></html>
"""

QRLIB = r'''/**
 * Minified by jsDelivr using Terser v5.37.0.
 * Original file: /npm/qrcode-generator@1.4.4/qrcode.js
 *
 * Do NOT use SRI with dynamically generated files! More information: https://www.jsdelivr.com/using-sri-with-dynamic-files
 */
var qrcode=function(){var t=function(t,r){var e=t,n=g[r],o=null,i=0,a=null,u=[],f={},c=function(t,r){o=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(i=4*e+17),l(0,0),l(i-7,0),l(0,i-7),s(),h(),d(t,r),e>=7&&v(t),null==a&&(a=p(e,n,u)),w(a,r)},l=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||i<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||i<=r+n||(o[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},h=function(){for(var t=8;t<i-8;t+=1)null==o[t][6]&&(o[t][6]=t%2==0);for(var r=8;r<i-8;r+=1)null==o[6][r]&&(o[6][r]=r%2==0)},s=function(){for(var t=B.getPatternPosition(e),r=0;r<t.length;r+=1)for(var n=0;n<t.length;n+=1){var i=t[r],a=t[n];if(null==o[i][a])for(var u=-2;u<=2;u+=1)for(var f=-2;f<=2;f+=1)o[i+u][a+f]=-2==u||2==u||-2==f||2==f||0==u&&0==f}},v=function(t){for(var r=B.getBCHTypeNumber(e),n=0;n<18;n+=1){var a=!t&&1==(r>>n&1);o[Math.floor(n/3)][n%3+i-8-3]=a}for(n=0;n<18;n+=1){a=!t&&1==(r>>n&1);o[n%3+i-8-3][Math.floor(n/3)]=a}},d=function(t,r){for(var e=n<<3|r,a=B.getBCHTypeInfo(e),u=0;u<15;u+=1){var f=!t&&1==(a>>u&1);u<6?o[u][8]=f:u<8?o[u+1][8]=f:o[i-15+u][8]=f}for(u=0;u<15;u+=1){f=!t&&1==(a>>u&1);u<8?o[8][i-u-1]=f:u<9?o[8][15-u-1+1]=f:o[8][15-u-1]=f}o[i-8][8]=!t},w=function(t,r){for(var e=-1,n=i-1,a=7,u=0,f=B.getMaskFunction(r),c=i-1;c>0;c-=2)for(6==c&&(c-=1);;){for(var g=0;g<2;g+=1)if(null==o[n][c-g]){var l=!1;u<t.length&&(l=1==(t[u]>>>a&1)),f(n,c-g)&&(l=!l),o[n][c-g]=l,-1==(a-=1)&&(u+=1,a=7)}if((n+=e)<0||i<=n){n-=e,e=-e;break}}},p=function(t,r,e){for(var n=A.getRSBlocks(t,r),o=b(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=k(i[u],l.getLength()-1).mod(l);for(a[u]=new Array(l.getLength()-1),g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=s>=0?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};f.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=M(t);break;case"Alphanumeric":e=x(t);break;case"Byte":e=m(t);break;case"Kanji":e=L(t);break;default:throw"mode:"+r}u.push(e),a=null},f.isDark=function(t,r){if(t<0||i<=t||r<0||i<=r)throw t+","+r;return o[t][r]},f.getModuleCount=function(){return i},f.make=function(){if(e<1){for(var t=1;t<40;t++){for(var r=A.getRSBlocks(t,n),o=b(),i=0;i<u.length;i++){var a=u[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var g=0;for(i=0;i<r.length;i++)g+=r[i].dataCount;if(o.getLengthInBits()<=8*g)break}e=t}c(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){c(!0,e);var n=B.getLostPoint(f);(0==e||t>n)&&(t=n,r=e)}return r}())},f.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<f.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<f.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=f.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},f.createSvgTag=function(t,r,e,n){var o={};"object"==typeof arguments[0]&&(t=(o=arguments[0]).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,c,g=f.getModuleCount()*t+2*r,l="";for(c="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",l+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',l+=o.scalable?"":' width="'+g+'px" height="'+g+'px"',l+=' viewBox="0 0 '+g+" "+g+'" ',l+=' preserveAspectRatio="xMinYMin meet"',l+=n.text||e.text?' role="img" aria-labelledby="'+y([n.id,e.id].join(" ").trim())+'"':"",l+=">",l+=n.text?'<title id="'+y(n.id)+'">'+y(n.text)+"</title>":"",l+=e.text?'<description id="'+y(e.id)+'">'+y(e.text)+"</description>":"",l+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',l+='<path d="',a=0;a<f.getModuleCount();a+=1)for(u=a*t+r,i=0;i<f.getModuleCount();i+=1)f.isDark(a,i)&&(l+="M"+(i*t+r)+","+u+c);return l+='" stroke="transparent" fill="black"/>',l+="</svg>"},f.createDataURL=function(t,r){t=t||2,r=void 0===r?4*t:r;var e=f.getModuleCount()*t+2*r,n=r,o=e-r;return I(e,e,(function(r,e){if(n<=r&&r<o&&n<=e&&e<o){var i=Math.floor((r-n)/t),a=Math.floor((e-n)/t);return f.isDark(a,i)?0:1}return 1}))},f.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=f.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=f.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=y(e),o+='"'),o+="/>"};var y=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return f.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*f.getModuleCount()+2*t,u=t,c=a-t,g={"██":"█","█ ":"▀"," █":"▄","  ":" "},l={"██":"▀","█ ":"▀"," █":" ","  ":" "},h="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<c&&u<=r&&r<c&&f.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<c&&u<=r+1&&r+1<c&&f.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",h+=t<1&&r+1>=c?l[i]:g[i];h+="\n"}return a%2&&t>0?h.substring(0,h.length-a-1)+Array(a+1).join("▀"):h.substring(0,h.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=f.getModuleCount()*t+2*r,u=r,c=a-r,g=Array(t+1).join("██"),l=Array(t+1).join("  "),h="",s="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),s="",n=0;n<a;n+=1)i=1,u<=n&&n<c&&u<=e&&e<c&&f.isDark(o,Math.floor((n-u)/t))&&(i=0),s+=i?g:l;for(o=0;o<t;o+=1)h+=s+"\n"}return h.substring(0,h.length-1)},f.renderTo2dContext=function(t,r){r=r||2;for(var e=f.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=f.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},f};t.stringToBytes=(t.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,t.createStringToBytes=function(t,r){var e=function(){for(var e=S(t),n=function(){var t=e.read();if(-1==t)throw"eof";return t},o=0,i={};;){var a=e.read();if(-1==a)break;var u=n(),f=n()<<8|n();i[String.fromCharCode(a<<8|u)]=f,o+=1}if(o!=r)throw o+" != "+r;return i}(),n="?".charCodeAt(0);return function(t){for(var r=[],o=0;o<t.length;o+=1){var i=t.charCodeAt(o);if(i<128)r.push(i);else{var a=e[t.charAt(o)];"number"==typeof a?(255&a)==a?r.push(a):(r.push(a>>>8),r.push(255&a)):r.push(n)}}return r}};var r,e,n,o,i,a=1,u=2,f=4,c=8,g={L:1,M:0,Q:3,H:2},l=0,h=1,s=2,v=3,d=4,w=5,p=6,y=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],e=1335,n=7973,i=function(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r},(o={}).getBCHTypeInfo=function(t){for(var r=t<<10;i(r)-i(e)>=0;)r^=e<<i(r)-i(e);return 21522^(t<<10|r)},o.getBCHTypeNumber=function(t){for(var r=t<<12;i(r)-i(n)>=0;)r^=n<<i(r)-i(n);return t<<12|r},o.getPatternPosition=function(t){return r[t-1]},o.getMaskFunction=function(t){switch(t){case l:return function(t,r){return(t+r)%2==0};case h:return function(t,r){return t%2==0};case s:return function(t,r){return r%3==0};case v:return function(t,r){return(t+r)%3==0};case d:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case w:return function(t,r){return t*r%2+t*r%3==0};case p:return function(t,r){return(t*r%2+t*r%3)%2==0};case y:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},o.getErrorCorrectPolynomial=function(t){for(var r=k([1],0),e=0;e<t;e+=1)r=r.multiply(k([1,C.gexp(e)],0));return r},o.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case f:case c:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case f:return 16;case c:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case f:return 16;case c:return 12;default:throw"mode:"+t}}},o.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);i>5&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},o),C=function(){for(var t=new Array(256),r=new Array(256),e=0;e<8;e+=1)t[e]=1<<e;for(e=8;e<256;e+=1)t[e]=t[e-4]^t[e-5]^t[e-6]^t[e-8];for(e=0;e<255;e+=1)r[t[e]]=e;var n={glog:function(t){if(t<1)throw"glog("+t+")";return r[t]},gexp:function(r){for(;r<0;)r+=255;for(;r>=256;)r-=255;return t[r]}};return n}();function k(t,r){if(void 0===t.length)throw t.length+"/"+r;var e=function(){for(var e=0;e<t.length&&0==t[e];)e+=1;for(var n=new Array(t.length-e+r),o=0;o<t.length-e;o+=1)n[o]=t[o+e];return n}(),n={getAt:function(t){return e[t]},getLength:function(){return e.length},multiply:function(t){for(var r=new Array(n.getLength()+t.getLength()-1),e=0;e<n.getLength();e+=1)for(var o=0;o<t.getLength();o+=1)r[e+o]^=C.gexp(C.glog(n.getAt(e))+C.glog(t.getAt(o)));return k(r,0)},mod:function(t){if(n.getLength()-t.getLength()<0)return n;for(var r=C.glog(n.getAt(0))-C.glog(t.getAt(0)),e=new Array(n.getLength()),o=0;o<n.getLength();o+=1)e[o]=n.getAt(o);for(o=0;o<t.getLength();o+=1)e[o]^=C.gexp(C.glog(t.getAt(o))+r);return k(e,0).mod(t)}};return n}var A=function(){var t=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],r=function(t,r){var e={};return e.totalCount=t,e.dataCount=r,e},e={};return e.getRSBlocks=function(e,n){var o=function(r,e){switch(e){case g.L:return t[4*(r-1)+0];case g.M:return t[4*(r-1)+1];case g.Q:return t[4*(r-1)+2];case g.H:return t[4*(r-1)+3];default:return}}(e,n);if(void 0===o)throw"bad rs block @ typeNumber:"+e+"/errorCorrectionLevel:"+n;for(var i=o.length/3,a=[],u=0;u<i;u+=1)for(var f=o[3*u+0],c=o[3*u+1],l=o[3*u+2],h=0;h<f;h+=1)a.push(r(c,l));return a},e}(),b=function(){var t=[],r=0,e={getBuffer:function(){return t},getAt:function(r){var e=Math.floor(r/8);return 1==(t[e]>>>7-r%8&1)},put:function(t,r){for(var n=0;n<r;n+=1)e.putBit(1==(t>>>r-n-1&1))},getLengthInBits:function(){return r},putBit:function(e){var n=Math.floor(r/8);t.length<=n&&t.push(0),e&&(t[n]|=128>>>r%8),r+=1}};return e},M=function(t){var r=a,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+2<r.length;)t.put(o(r.substring(n,n+3)),10),n+=3;n<r.length&&(r.length-n==1?t.put(o(r.substring(n,n+1)),4):r.length-n==2&&t.put(o(r.substring(n,n+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return n},x=function(t){var r=u,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+1<r.length;)t.put(45*o(r.charAt(n))+o(r.charAt(n+1)),11),n+=2;n<r.length&&t.put(o(r.charAt(n)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return n},m=function(r){var e=f,n=t.stringToBytes(r),o={getMode:function(){return e},getLength:function(t){return n.length},write:function(t){for(var r=0;r<n.length;r+=1)t.put(n[r],8)}};return o},L=function(r){var e=c,n=t.stringToBytesFuncs.SJIS;if(!n)throw"sjis not supported.";!function(){var t=n("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=n(r),i={getMode:function(){return e},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return i},D=function(){var t=[],r={writeByte:function(r){t.push(255&r)},writeShort:function(t){r.writeByte(t),r.writeByte(t>>>8)},writeBytes:function(t,e,n){e=e||0,n=n||t.length;for(var o=0;o<n;o+=1)r.writeByte(t[o+e])},writeString:function(t){for(var e=0;e<t.length;e+=1)r.writeByte(t.charCodeAt(e))},toByteArray:function(){return t},toString:function(){var r="";r+="[";for(var e=0;e<t.length;e+=1)e>0&&(r+=","),r+=t[e];return r+="]"}};return r},S=function(t){var r=t,e=0,n=0,o=0,i={read:function(){for(;o<8;){if(e>=r.length){if(0==o)return-1;throw"unexpected end of file./"+o}var t=r.charAt(e);if(e+=1,"="==t)return o=0,-1;t.match(/^\s$/)||(n=n<<6|a(t.charCodeAt(0)),o+=6)}var i=n>>>o-8&255;return o-=8,i}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return i},I=function(t,r,e){for(var n=function(t,r){var e=t,n=r,o=new Array(t*r),i={setPixel:function(t,r,n){o[r*e+t]=n},write:function(t){t.writeString("GIF87a"),t.writeShort(e),t.writeShort(n),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(e),t.writeShort(n),t.writeByte(0);var r=a(2);t.writeByte(2);for(var o=0;r.length-o>255;)t.writeByte(255),t.writeBytes(r,o,255),o+=255;t.writeByte(r.length-o),t.writeBytes(r,o,r.length-o),t.writeByte(0),t.writeString(";")}},a=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,i=u(),a=0;a<r;a+=1)i.add(String.fromCharCode(a));i.add(String.fromCharCode(r)),i.add(String.fromCharCode(e));var f,c,g,l=D(),h=(f=l,c=0,g=0,{write:function(t,r){if(t>>>r!=0)throw"length over";for(;c+r>=8;)f.writeByte(255&(t<<c|g)),r-=8-c,t>>>=8-c,g=0,c=0;g|=t<<c,c+=r},flush:function(){c>0&&f.writeByte(g)}});h.write(r,n);var s=0,v=String.fromCharCode(o[s]);for(s+=1;s<o.length;){var d=String.fromCharCode(o[s]);s+=1,i.contains(v+d)?v+=d:(h.write(i.indexOf(v),n),i.size()<4095&&(i.size()==1<<n&&(n+=1),i.add(v+d)),v=d)}return h.write(i.indexOf(v),n),h.write(e,n),h.flush(),l.toByteArray()},u=function(){var t={},r=0,e={add:function(n){if(e.contains(n))throw"dup key:"+n;t[n]=r,r+=1},size:function(){return r},indexOf:function(r){return t[r]},contains:function(r){return void 0!==t[r]}};return e};return i}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=D();n.write(a);for(var u=function(){var t=0,r=0,e=0,n="",o={},i=function(t){n+=String.fromCharCode(a(63&t))},a=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return o.writeByte=function(n){for(t=t<<8|255&n,r+=8,e+=1;r>=6;)i(t>>>r-6),r-=6},o.flush=function(){if(r>0&&(i(t<<6-r),t=0,r=0),e%3!=0)for(var o=3-e%3,a=0;a<o;a+=1)n+="="},o.toString=function(){return n},o}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return t}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||n>=57344?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}((function(){return qrcode}));
//# sourceMappingURL=/sm/26b4b0d0b1e283d6b3ec9857ac597d7a60c76ac17be1ef4c965f03086de426bb.map'''

PANEL_HTML = r"""
<!doctype html><html><head><meta charset="utf-8">
<title>admin</title>
<style>""" + BASE_CSS + r"""</style>
<script>""" + QRLIB + r"""</script></head>
<body>
<div class="topbar">
  <div class="brand"><span class="logo"></span> admin</div>
  <div style="display:flex;align-items:center;gap:12px;">
    <button type="button" class="theme-btn" id="themeBtn" onclick="toggleTheme()" title="切换日夜主题">☾</button>
    <span class="tag mono" title="版本">v1.10</span>
    <a class="logout-link" href="javascript:void(0)" onclick="openPwModal()">修改密码</a>
    <a class="logout-link" href="{{ url_for('panel.logout') }}">退出登录</a>
  </div>
</div>

<div class="wrap">
  {% if flash_msg %}
    <script>var INIT_FLASH = {{ ({"m": flash_msg, "t": flash_type}) | tojson }};</script>
  {% else %}
    <script>var INIT_FLASH = null;</script>
  {% endif %}

  {% if allowlist_hint %}
  <div class="panel" id="allowlist-hint" style="border-left:4px solid #f0a020;">
    <div class="panel-head" style="border-bottom:none;">
      <span style="color:#c67c00;">⚠ 安全提示：面板端口当前对任意 IP（Anywhere）开放</span>
      <span style="flex:1;"></span>
      <button type="button" class="btn-sm" onclick="ackAllowlist()">知道了</button>
    </div>
    <div style="padding:0 20px 14px;font-size:13px;color:#5a6472;">
      建议尽快在下方『<b>防火墙</b>』卡片中「放行当前 IP」，并删除面板端口的 Anywhere 规则，把面板限制为白名单 IP 访问。
    </div>
  </div>
  {% endif %}

  <div class="panel" id="sys-status">
    <div class="panel-head">
      <span>系统状态</span>
      <button type="button" class="btn-sm" onclick="restartXray()">重启 xray</button>
    </div>
    <div id="restart-msg" class="flash-msg" style="display:none;"></div>
    <div class="sv-grid">
      <div class="sv-gauge-cell">
        <div class="gauge" id="g-cpu" style="--p:0;"><span id="g-cpu-t">0%</span></div>
        <div class="gauge-label">CPU · <b id="g-cpu-sub">0 core</b></div>
      </div>
      <div class="sv-gauge-cell">
        <div class="gauge" id="g-mem" style="--p:0;"><span id="g-mem-t">0%</span></div>
        <div class="gauge-label">内存 · <b id="g-mem-sub">-</b></div>
      </div>
      <div class="sv-gauge-cell">
        <div class="gauge" id="g-swap" style="--p:0;"><span id="g-swap-t">0%</span></div>
        <div class="gauge-label">Swap · <b id="g-swap-sub">-</b></div>
      </div>
      <div class="sv-gauge-cell">
        <div class="gauge" id="g-disk" style="--p:0;"><span id="g-disk-t">0%</span></div>
        <div class="gauge-label">磁盘 · <b id="g-disk-sub">-</b></div>
      </div>
    </div>
    <div class="sv-grid sv-grid-lines">
      <div class="kv"><div class="k">xray 状态</div><div class="v" id="sv-xray">—</div></div>
      <div class="kv"><div class="k">系统运行时间 <span class="note">自开机</span></div><div class="v" id="sv-uptime">—</div></div>
      <div class="kv"><div class="k">系统负载</div><div class="v" id="sv-load">—</div></div>
      <div class="kv"><div class="k">连接数</div><div class="v"><span id="sv-tcp">0</span> tcp · <span id="sv-udp">0</span> udp</div></div>
      <div class="kv"><div class="k">实时速度</div><div class="v stat-inline"><span class="traffic-up">↑ <span id="sv-net-up">0 B/s</span></span><span class="traffic-down">↓ <span id="sv-net-down">0 B/s</span></span></div></div>
      <div class="kv"><div class="k">节点服务流量 <span class="note">累计</span></div><div class="v stat-inline"><span class="traffic-up">↑ <span id="sv-tot-up">0</span></span><span class="traffic-down">↓ <span id="sv-tot-down">0</span></span></div></div>
      <div class="kv"><div class="k">网卡总流量 <span class="note">自开机</span></div><div class="v stat-inline"><span class="traffic-up">↑ <span id="sv-nic-up">0</span></span><span class="traffic-down">↓ <span id="sv-nic-down">0</span></span></div></div>
      <div class="kv"><div class="k">最后刷新</div><div class="v" id="sv-tick">—</div></div>
    </div>
  </div>

{% if error %}
  <div class="panel"><div class="empty-state">读取配置失败：{{ error }}</div></div>
{% else %}

<div class="panel" id="vless-panel">
    <div class="panel-head">
      <span>vless 节点</span>
      <span class="count">{{ nodes|length }}</span>
      <button type="button" class="btn-sm" onclick="openVlessModal()">+ 节 点</button>
    </div>
    {% if nodes %}
    <table>
      <tr><th>名称</th><th>端口</th><th>安全 · 网络</th><th>SNI</th><th>状态</th><th>操作</th></tr>
      <colgroup>
        <col style="width:12%"><col style="width:10%"><col style="width:16%"><col style="width:28%"><col style="width:10%"><col style="width:24%">
      </colgroup>
      {% for n in nodes %}
      <tr class="{{ 'paused' if n.status == 'paused' else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ n.seq_name }}</span></td>
        <td class="mono">{{ n.port }}</td>
        <td>{{ n.security }} · {{ n.network }}</td>
        <td class="mono" style="font-size:11.5px;">{{ n.sni }}</td>
        <td>
          {% if n.status == 'paused' %}
            <span class="tag status-pause">已暂停</span>
          {% else %}
            <span class="tag status-run">运行中</span>
          {% endif %}
        </td>
        <td>
          <div class="row-actions">
            <form class="async-form" method="post" action="{{ url_for('panel.inbound_toggle', port=n.port) }}" style="margin:0;">
              {% if n.status == 'paused' %}
                <button type="submit" class="btn-sm-resume">恢复</button>
              {% else %}
                <button type="submit" class="btn-sm-warn" {{ 'disabled' if n.protected else '' }}>暂停</button>
              {% endif %}
            </form>
            <form class="async-form" method="post" action="{{ url_for('panel.inbound_delete', port=n.port) }}" style="margin:0;" data-confirm="确定删除入站端口 {{ n.port }}？其下客户端将被一并移除。">
              <button type="submit" class="btn-sm-danger" {{ 'disabled' if n.protected else '' }}>删除</button>
            </form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <div class="empty-state">暂无 vless 入站</div>
    {% endif %}
  </div>

  <div class="panel" id="hy2-panel">
    <div class="panel-head">
      <span>hy2 节点</span>
      <span class="count">{{ hy2_nodes|length }}</span>
      <button type="button" class="btn-sm" onclick="openHy2Modal()">+ 节 点</button>
    </div>
    {% if hy2_nodes %}
    <table>
      <tr><th>名称</th><th>端口</th><th>安全 · 网络</th><th>SNI</th><th>状态</th><th>操作</th></tr>
      <colgroup>
        <col style="width:12%"><col style="width:10%"><col style="width:16%"><col style="width:28%"><col style="width:10%"><col style="width:24%">
      </colgroup>
      {% for h in hy2_nodes %}
      <tr class="{{ 'paused' if not h.enabled else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ h.seq_name }}</span></td>
        <td class="mono">{{ h.port }}</td>
        <td>{{ h.security }} · {{ h.network }}</td>
        <td class="mono" style="font-size:11.5px;">{{ h.sni }}</td>
        <td>
          {% if h.enabled %}
            <span class="tag status-run">运行中</span>
          {% else %}
            <span class="tag status-pause">已暂停</span>
          {% endif %}
        </td>
        <td>
          <div class="row-actions">
            <form class="async-form" method="post" action="{{ url_for('panel.hy2node_toggle', node_id=h.id) }}" style="margin:0;">
              {% if h.enabled %}
                <button type="submit" class="btn-sm-warn" {{ 'disabled' if h.protected else '' }}>暂停</button>
              {% else %}
                <button type="submit" class="btn-sm-resume">恢复</button>
              {% endif %}
            </form>
            <form class="async-form" method="post" action="{{ url_for('panel.hy2node_delete', node_id=h.id) }}" style="margin:0;" data-confirm="确定删除 Hysteria2 节点 {{ h.seq_name }}？其全部用户将被移除，对应服务停止。">
              <button type="submit" class="btn-sm-danger" {{ 'disabled' if h.protected else '' }}>删除</button>
            </form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <div class="empty-state">暂无 Hysteria2 节点</div>
    {% endif %}
  </div>

  <div class="panel" id="fwd-panel">
    <div class="panel-head">
      <span>中转</span>
      <span class="count">{{ fwd_nodes|length }}</span>
      <button type="button" class="btn-sm" onclick="openFwdModal()">+ 转 发</button>
    </div>
    {% if fwd_nodes %}
    <table>
      <tr><th>名称</th><th>本机端口</th><th>目标</th><th>协议</th><th>流量</th><th>状态</th><th>操作</th></tr>
      <colgroup>
        <col style="width:12%"><col style="width:10%"><col style="width:22%"><col style="width:10%"><col style="width:16%"><col style="width:8%"><col style="width:22%">
      </colgroup>
      {% for f in fwd_nodes %}
      <tr class="{{ 'paused' if not f.enabled else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ f.seq_name }}</span></td>
        <td class="mono">{{ f.listen_port }}</td>
        <td class="mono" style="font-size:11.5px;">{{ f.target_ip }}:{{ f.target_port }}</td>
        <td class="mono">{{ f.proto }}</td>
        <td style="white-space:nowrap;">
          <span class="traffic-up">↑ {{ f.up }}</span><br>
          <span class="traffic-down">↓ {{ f.down }}</span>
        </td>
        <td>
          {% if f.enabled %}
            <span class="tag status-run">运行中</span>
          {% else %}
            <span class="tag status-pause">已暂停</span>
          {% endif %}
        </td>
        <td>
          <div class="row-actions">
            <form class="async-form" method="post" action="{{ url_for('panel.fwd_toggle', rule_id=f.id) }}" style="margin:0;">
              {% if f.enabled %}
                <button type="submit" class="btn-sm-warn" {{ 'disabled' if f.protected else '' }}>暂停</button>
              {% else %}
                <button type="submit" class="btn-sm-resume">恢复</button>
              {% endif %}
            </form>
            <form class="async-form" method="post" action="{{ url_for('panel.fwd_delete', rule_id=f.id) }}" style="margin:0;" data-confirm="确定删除中转 {{ f.seq_name }} (本机 :{{ f.listen_port }} → {{ f.target_ip }}:{{ f.target_port }})？">
              <button type="submit" class="btn-sm-danger" {{ 'disabled' if f.protected else '' }}>删除</button>
            </form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <div class="empty-state">暂无中转规则</div>
    {% endif %}
  </div>

  <div class="panel" id="admin-panel">
    <style>
      #admin-panel{overflow:visible;}
      #admin-panel .admin-scroll{overflow-x:auto;}
      #admin-panel .admin-actions{display:flex;flex-wrap:wrap;gap:6px;}
      #admin-panel .admin-add-form{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:14px 20px;border-top:1px solid #eceff2;margin:0;}
      #admin-panel .admin-add-form input{padding:8px 10px;font-size:13px;border:1px solid #dfe3e8;border-radius:6px;min-width:190px;}
      #admin-panel table{min-width:640px;}
      #admin-panel td,#admin-panel th{vertical-align:middle;white-space:nowrap;}
      .limit-switch{position:relative;display:inline-block;width:44px;height:24px;flex:0 0 auto;}
      .limit-switch input{opacity:0;width:0;height:0;}
      .limit-slider{position:absolute;cursor:pointer;inset:0;background:#cfd6df;border-radius:24px;transition:.2s;}
      .limit-slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;}
      .limit-switch input:checked + .limit-slider{background:#2f6fed;}
      .limit-switch input:checked + .limit-slider:before{transform:translateX(20px);}
    </style>
    <div class="panel-head">
      <span>limit用户</span>
      <span style="flex:1;"></span>
      <label class="limit-switch" title="开启 / 关闭 limit用户管理">
        <input type="checkbox" id="limitToggle" {% if limit_on %}checked{% endif %}>
        <span class="limit-slider"></span>
      </label>
    </div>
    <div id="admin-body"{% if not limit_on %} style="display:none;"{% endif %}>
      <div style="padding:10px 20px;font-size:12px;color:#8a929e;border-bottom:1px solid #f2f4f6;">共 <b style="color:#2f6fed;">{{ tenants|length }}</b> 个 limit用户</div>
      {% if tenants %}
      <div class="admin-scroll">
      <table>
        <tr><th>名称</th><th>端口</th><th>账号</th><th>流量</th><th>状态</th><th>操作</th></tr>
        {% for t in tenants %}
        <tr class="{{ 'paused' if t.exhausted else '' }}">
          <td>{{ t.name }}</td>
          <td class="mono">{{ t.port }}</td>
          <td class="mono">{{ t.user }}</td>
          <td style="white-space:nowrap;">{{ t.used_h }} / {{ t.quota_h }} ({{ t.pct }}%)</td>
          <td>{% if t.exhausted %}<span class="tag status-pause">已耗尽</span>{% else %}<span class="tag status-run">正常</span>{% endif %}</td>
          <td>
            <div class="admin-actions">
              <button type="button" class="btn-sm-reset" onclick="copyText('{{ t.addr }}','已复制地址')">复制地址</button>
              <button type="button" class="btn-sm-reset" onclick="copyText('{{ t.pass }}','已复制密码')">复制密码</button>
              <form class="async-form" method="post" action="{{ url_for('panel.admin_reset', tid=t.id) }}" style="margin:0;">
                <button type="submit" class="btn-sm-warn">重置</button>
              </form>
              <form class="async-form" method="post" action="{{ url_for('panel.admin_delete', tid=t.id) }}" style="margin:0;" data-confirm="删除limit用户 {{ t.name }} 及其全部节点/中转？">
                <button type="submit" class="btn-sm-danger">删除</button>
              </form>
            </div>
          </td>
        </tr>
        {% endfor %}
      </table>
      </div>
      {% else %}
        <div class="empty-state">暂无limit用户</div>
      {% endif %}
      <form class="async-form admin-add-form" method="post" action="{{ url_for('panel.admin_add') }}">
        <input type="text" name="name" placeholder="limit用户名称" required autocomplete="off">
        <input type="text" name="quota_gb" placeholder="总流量配额(GB)" required autocomplete="off">
        <button type="submit" class="btn-sm">+ 增加limit用户</button>
      </form>
    </div>
  </div>
  <div class="panel" id="clients-panel">
    <div class="panel-head">
      <span>用户</span>
      <span class="count">{{ clients|length }}</span>
      <button type="button" class="btn-sm" onclick="openAddUserModal()">+ 用户</button>
    </div>
    {% if clients %}
    <table>
      <tr><th>用户</th><th>绑定节点</th><th>流量（上传/下载）</th><th>状态</th><th>操作</th></tr>
      {% for c in clients %}
      <tr class="{{ 'paused' if c.status == 'paused' else '' }}" data-cid="{{ c.id }}" data-type="user" data-admin="{{ '1' if c.is_admin else '' }}">
        <td><span class="mono">{{ c.label }}</span></td>
        <td>
          <div class="node-chips">
            {% for nc in c.nodes %}
              <span class="node-chip{{ ' chip-protected' if nc.protected else '' }}" data-kind="{{ nc.kind }}" data-key="{{ nc.key }}" title="{{ nc.title or nc.label }}">{{ nc.label }}</span>
            {% else %}
              <span class="badge-flow">未绑定节点</span>
            {% endfor %}
          </div>
        </td>
        <td>
          <span class="traffic-up">↑ {{ c.up }}</span><br>
          <span class="traffic-down">↓ {{ c.down }}</span>
        </td>
        <td>
          {% if c.status == 'paused' %}
            <span class="tag status-pause">已暂停</span>
          {% else %}
            <span class="tag status-run">运行中</span>
          {% endif %}
        </td>
        <td>
          <div class="row-actions">
            <button type="button" class="btn-sm" onclick="openAddNodeModal('{{ c.id }}')">节点</button>
            <button type="button" class="btn-sm" onclick="exportUserYaml('{{ c.id }}')" title="导出该用户名下所有启用节点（mihomo/Clash YAML）">导出YAML</button>
            <button type="button" class="btn-sm" onclick="exportUserLink('{{ c.id }}')" title="复制标准分享链接（vless:// / hysteria2://）">复制链接</button>
            <button type="button" class="btn-sm" onclick="showUserQR('{{ c.id }}','{{ c.label|e }}')" title="显示节点二维码">二维码</button>
            <form class="async-form" method="post" action="{{ url_for('panel.user_toggle', name=c.id) }}" style="margin:0;">
              {% if c.status == 'paused' %}
                <button type="submit" class="btn-sm-resume">恢复</button>
              {% else %}
                <button type="submit" class="btn-sm-warn">暂停</button>
              {% endif %}
            </form>
            <button type="button" class="btn-sm-reset" {{ 'disabled' if not (c.has_hy2 or c.has_vless) else '' }} onclick="openHy2PassModal('{{ c.id }}')" title="{{ '修改该用户的 vless UUID 与 hy2 密码' if (c.has_hy2 or c.has_vless) else '该用户未绑定任何节点' }}">uuid/密码</button>
            <form class="async-form" method="post" action="{{ url_for('panel.user_reset_traffic', name=c.id) }}" style="margin:0;" data-confirm="清零 {{ c.label }} 的流量？">
              <button type="submit" class="btn-sm-reset">清零</button>
            </form>
            <form class="async-form" method="post" action="{{ url_for('panel.user_delete', name=c.id) }}" style="margin:0;" data-confirm="删除用户 {{ c.label }}？将从全部节点移除。">
              <button type="submit" class="btn-sm-danger">删除</button>
            </form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <div class="empty-state">暂无用户</div>
    {% endif %}
  </div>

  <div class="panel" id="fw-panel">
    <div class="panel-head">
      <span>防火墙</span>
      <span class="count" id="fw-count"></span>
      <span style="flex:1;"></span>
      <button type="button" class="btn-sm" onclick="loadFirewall()">刷新</button>
      <button type="button" class="btn-sm" onclick="allowMyIp()" title="放行当前访问 IP 访问面板端口，避免误删规则把面板锁掉">放行当前 IP</button>
    </div>
    <div id="fw-body">
      <div class="empty-state">正在读取 ufw 规则…</div>
    </div>
    <div class="fw-add" style="padding:14px 20px;border-top:1px solid #eceff2;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <span style="font-size:12px;color:#8a929e;">放行</span>
      <input type="number" id="fw-port" min="1" max="65535" placeholder="端口" autocomplete="off" style="width:120px;padding:7px 10px;border:1px solid #dfe3e8;border-radius:6px;">
      <select id="fw-proto" style="padding:7px 10px;border:1px solid #dfe3e8;border-radius:6px;">
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
        <option value="both">tcp+udp</option>
      </select>
      <button type="button" class="btn-sm" onclick="fwAllowPort()">+ 放行端口</button>
      <span style="font-size:12px;color:#8a929e;">或</span>
      <input type="text" id="fw-ip" placeholder="来源 IP" autocomplete="off" style="width:150px;padding:7px 10px;border:1px solid #dfe3e8;border-radius:6px;">
      <button type="button" class="btn-sm" onclick="fwAllowIp()">+ 放行 IP→端口</button>
      <span class="hint" style="margin-left:auto;font-size:11.5px;">删除会锁死当前 IP 的规则将被拒绝，面板端口由系统自动保护</span>
    </div>
  </div>

  <div class="footer-note">最后更新：{{ last_update }}（流量每 5 秒后台同步）</div>
{% endif %}
</div>

<div class="modal-backdrop" id="vlessModal">
  <div class="modal-box" style="width:520px;">
    <h3 id="vlessModalTitle">添加 vless 入站</h3>
    <form method="post" id="vlessForm" class="async-form">
      <div class="form-grid">
        <div class="full" id="vl-remark-row">
          <label>节点名称</label>
          <input type="text" name="remark" id="vl-remark" autocomplete="off" placeholder="vless2">
        </div>
        <div>
          <label>端口</label>
          <input type="number" name="port" id="vl-port" min="1" max="65535" required>
        </div>
        <div id="vl-security-row">
          <label>安全</label>
          <select name="security" id="vl-security" onchange="vlGroup()">
            <option value="reality">REALITY</option>
            <option value="tls">TLS</option>
            <option value="none">无</option>
          </select>
        </div>
        <div id="vl-network-row">
          <label>网络</label>
          <select name="network" id="vl-network" onchange="vlGroup()">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="grpc">gRPC</option>
          </select>
        </div>
        <div class="full">
          <label>域名 / SNI</label>
          <div style="display:flex;gap:8px;">
            <input type="text" name="sni" id="vl-sni" autocomplete="off" placeholder="www.amazon.com" style="flex:1;min-width:0;">
            <button type="button" class="btn-sm-reset" onclick="switchSni('vless')" style="flex-shrink:0;margin-top:0;" title="随机切换为另一个预置高可用性域名">换</button>
          </div>
        </div>
        <div class="full" id="vl-dest-row">
          <label>REALITY 目标（dest）</label>
          <input type="text" name="dest" id="vl-dest" autocomplete="off" placeholder="www.amazon.com:443">
        </div>
        <div class="full hidden" id="vl-wspath-row">
          <label>WebSocket 路径</label>
          <input type="text" name="ws_path" id="vl-wspath" autocomplete="off" placeholder="/">
        </div>
        <div class="full hidden" id="vl-grpc-row">
          <label>gRPC serviceName</label>
          <input type="text" name="grpc_service" id="vl-grpc" autocomplete="off" placeholder="vless">
        </div>
        <div class="full" id="vl-keys">
          <label>REALITY 密钥</label>
          <div class="mono" id="vl-pub" style="word-break:break-all;background:#fafbfc;padding:7px 9px;border:1px solid #eceff2;border-radius:6px;">—</div>
          <input type="hidden" name="reality_private" id="vl-priv" value="">
          <input type="hidden" name="reality_public" id="vl-pub2" value="">
          <button type="button" class="btn-sm-reset" onclick="genKeys()">生成 / 刷新密钥</button>
          <div class="hint">PrivateKey 写 xray 配置；PublicKey 供客户端分享。</div>
        </div>
      </div>
      <div class="modal-actions" style="margin-top:18px;">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">保存节点</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="hy2Modal">
  <div class="modal-box" style="width:520px;">
    <h3 id="hy2ModalTitle">添加 Hysteria2 节点</h3>
    <form method="post" id="hy2Form" class="async-form">
      <div class="form-grid">
        <div class="full">
          <label>节点名称</label>
          <input type="text" name="name" id="hy2-name" required autocomplete="off" placeholder="Node2">
        </div>
        <div>
          <label>端口（UDP）</label>
          <input type="number" name="port" id="hy2-port" min="1" max="65535" required>
        </div>
        <div id="hy2-stats-row">
          <label>流量统计端口</label>
          <input type="number" name="stats_port" id="hy2-stats" min="1" max="65535" placeholder="留空自动" autocomplete="off">
          <div class="hint">本机 127.0.0.1 上的独立端口</div>
        </div>
        <div class="full" id="hy2-masq-row">
          <label>伪装网站（masquerade）</label>
          <input type="text" name="masquerade" id="hy2-masq" required autocomplete="off" placeholder="https://www.amazon.com">
        </div>
        <div class="full">
          <label>域名 / SNI（留空自动取伪装网站域名）</label>
          <div style="display:flex;gap:8px;">
            <input type="text" name="sni" id="hy2-sni" autocomplete="off" placeholder="www.amazon.com" style="flex:1;min-width:0;">
            <button type="button" class="btn-sm-reset" onclick="switchSni('hy2')" style="flex-shrink:0;margin-top:0;" title="随机切换为另一个预置高可用性域名">换</button>
          </div>
        </div>
        <div class="full" id="hy2-cert-hint">
          <div class="hint">证书固定用自签 server.crt，客户端需开启「信任自签证书」。用户在节点列表中添加。</div>
        </div>
      </div>
      <div class="modal-actions" style="margin-top:18px;">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">保存节点</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="fwdModal">
  <div class="modal-box" style="width:480px;">
    <h3 id="fwdModalTitle">添加中转</h3>
    <form method="post" id="fwdForm" class="async-form">
      <div class="form-grid">
        <div class="full">
          <label>名称</label>
          <input type="text" name="name" id="fwd-name" required autocomplete="off" placeholder="fwd1">
        </div>
        <div>
          <label>本机端口</label>
          <input type="number" name="port" id="fwd-port" min="1" max="65535" required>
        </div>
        <div>
          <label>目标端口</label>
          <input type="number" name="target_port" id="fwd-tport" min="1" max="65535" required>
        </div>
        <div class="full">
          <label>目标 IP / 域名</label>
          <input type="text" name="target_ip" id="fwd-tip" required autocomplete="off" placeholder="1.2.3.4">
          <div class="hint">纯转发，自动 TCP + UDP，只搬运字节不处理数据</div>
        </div>
      </div>
      <div class="modal-actions" style="margin-top:18px;">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">保存</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="addUserModal">
  <div class="modal-box" style="width:480px;">
    <h3>添加用户</h3>
    <form method="post" id="addUserForm" action="" class="async-form">
      <div class="form-grid">
        <div class="full">
          <label>用户名称（唯一）</label>
          <input type="text" name="name" id="au-name" required autocomplete="off" placeholder="user-01">
        </div>
      </div>
      <div class="full" style="margin-top:14px;">
        <div class="modal-sub-label">添加到以下节点（可多选）</div>
        <div class="node-check-list" id="au-node-list">
        </div>
      </div>
      <div class="hint" id="au-hint">创建后自动生成 vless UUID / hy2 密码。</div>
      <div class="modal-actions">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">确认添加</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="pwModal">
  <div class="modal-box" style="width:420px;">
    <h3>修改面板密码</h3>
    <form class="async-form" method="post" action="{{ url_for('panel.change_password') }}">
      <div class="full"><label>原密码</label><input type="password" name="old" required autocomplete="current-password"></div>
      <div class="full" style="margin-top:12px;"><label>新密码（至少 8 位）</label><input type="password" name="new" required minlength="8" autocomplete="new-password"></div>
      <div class="modal-actions">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">确认修改</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="addNodeModal">
  <div class="modal-box" style="width:520px;">
    <h3 id="addNodeTitle">为用户添加节点</h3>
    <div class="an-sec-head">已绑定节点</div>
    <div class="node-check-list" id="an-bound-list">
    </div>
    <form method="post" id="addNodeForm" action="" class="async-form">
      <div class="an-sec-head" style="margin-top:12px;">可添加节点</div>
      <div class="node-check-list" id="an-node-list">
      </div>
      <div class="modal-actions">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">确认添加</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="hy2PassModal">
  <div class="modal-box">
    <h3>修改 uuid/密码</h3>
    <form method="post" id="hy2PassForm" class="async-form">
      <div class="form-grid">
        <div class="full">
          <label>用户名</label>
          <div class="mono" id="hp-label" style="background:#fafbfc;padding:8px 10px;border:1px solid #eceff2;border-radius:6px;">—</div>
        </div>
        <div class="full">
          <label>新 uuid / 密码（UUID 格式；同步到该用户绑定的全部 hy2 节点，若绑定 vless 则同步更新其 uuid）</label>
          <div style="display:flex;gap:8px;">
            <input type="text" name="newpass" id="hp-pass" required autocomplete="off" spellcheck="false" style="flex:1;min-width:0;font-family:'SFMono-Regular',Consolas,monospace;">
            <button type="button" class="btn-sm-reset" onclick="genUuidPass()" style="flex-shrink:0;margin-top:0;" title="自动生成 UUID 格式密码">生成</button>
          </div>
          <div class="hint">点「生成」随机生成 UUID；此值将同时作为该用户在 vless 上的新 uuid 与其各 hy2 节点密码。</div>
        </div>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn-cancel" onclick="closeModals()">取消</button>
        <button type="submit" class="btn-sm">确认修改</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop" id="qrModal">
  <div class="modal-box" style="width:380px;text-align:center;">
    <h3 id="qrTitle" style="text-align:left;">节点二维码</h3>
    <div id="qrBox" style="display:flex;justify-content:center;align-items:center;padding:8px 0;min-height:220px;"></div>
    <div class="mono" id="qrLink" style="font-size:11px;color:#8a929e;word-break:break-all;white-space:pre-wrap;max-height:80px;overflow:auto;text-align:left;background:#fafbfc;padding:8px;border-radius:6px;"></div>
    <div class="modal-actions" style="margin-top:16px;">
      <button type="button" class="btn-cancel" onclick="closeModals()">关闭</button>
    </div>
  </div>
</div>

<script>
(function() {
  function applyTheme(theme) {
    var root = document.documentElement;
    if (theme === 'dark') { root.classList.add('dark'); }
    else { root.classList.remove('dark'); }
    var btn = document.getElementById('themeBtn');
    if (btn) { btn.textContent = theme === 'dark' ? '☀' : '☾'; }
  }
  window.toggleTheme = function() {
    var root = document.documentElement;
    var next = root.classList.contains('dark') ? 'light' : 'dark';
    try { localStorage.setItem('panel_theme', next); } catch (e) {}
    applyTheme(next);
  };
  var saved = null;
  try { saved = localStorage.getItem('panel_theme'); } catch (e) {}
  if (saved) { applyTheme(saved); }
})();
let NODES = {{ nodes_json|safe }};
let HY2 = {{ hy2_json|safe }};
let FWD = {{ fwd_json|safe }};
const APIBASE = '{{ url_for("panel.index") }}';
var svXrayWasRunning = Date.now();
const REALITY_SITES = ["www.amazon.com","www.google.com","www.cloudflare.com","www.microsoft.com","www.apple.com","www.netflix.com","www.youtube.com","www.wikipedia.org","www.github.com","www.zoom.us","www.discord.com","www.linkedin.com","www.facebook.com","www.bing.com","www.office.com","www.shopify.com","www.salesforce.com","www.adobe.com","www.spotify.com","www.twitch.tv"];
const LINKED_SNI_ROW = 'vl-sni';
function randomOpenPort(){
  const used = new Set([10085]);
  NODES.forEach(n => used.add(Number(n.port)));
  HY2.forEach(h => used.add(Number(h.port)));
  FWD.forEach(f => used.add(Number(f.listen_port)));
  for (let i = 0; i < 200; i++) {
    const p = 1000 + Math.floor(Math.random() * 60000);
    if (!used.has(p)) return p;
  }
  return 20000 + Math.floor(Math.random() * 1000);
}
function randomSite(){ return REALITY_SITES[Math.floor(Math.random() * REALITY_SITES.length)]; }
function switchSni(which){
  const cur = $('vl-sni').value;
  let next = randomSite();
  let guard = 0;
  while (next === cur && guard++ < 20) next = randomSite();
  if (which === 'hy2') {
    $('hy2-sni').value = next;
    if (!$('hy2-masq-row').classList.contains('hidden')) {
      $('hy2-masq').value = 'https://' + next;
    }
  } else {
    $('vl-sni').value = next;
    if (!$('vl-dest-row').classList.contains('hidden')) {
      $('vl-dest').value = next + ':443';
    }
  }
}
function closeModals(){ ['vlessModal','hy2Modal','fwdModal','addUserModal','addNodeModal','hy2PassModal','qrModal','pwModal'].forEach(id => { const el = $(id); if (el) el.classList.remove('open'); }); }
function openPwModal(){ $('pwModal').classList.add('open'); }
function showQR(text, title){
  $('qrTitle').textContent = title || '节点二维码';
  $('qrLink').textContent = text || '';
  const box = $('qrBox');
  box.innerHTML = '';
  try {
    const qr = qrcode(0, 'L');
    qr.addData(text || '');
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
  } catch (e) { box.innerHTML = '<div class="empty-state">生成二维码失败</div>'; }
  $('qrModal').classList.add('open');
}
async function showUserQR(name, label){
  try {
    const r = await fetch(APIBASE + 'user/export_link/' + encodeURIComponent(name), { method: 'POST' });
    if (!r.ok) { showToastErr('读取失败：' + (await r.text())); return; }
    // 多节点：每个链接单独一行（换行分隔）
    const txt = (await r.text()).trim().split(/\s+/).filter(Boolean).join('\n');
    showQR(txt, label ? ('二维码 · ' + label) : '节点二维码');
  } catch (e) { showToastErr('读取失败：' + e); }
}
function openAddUserModal(){
  $('addUserForm').reset();
  const list = $('au-node-list');
  list.innerHTML = '';
  let any = false;
  NODES.forEach(n => {
    any = true;
    const lab = document.createElement('label');
    lab.className = 'node-check-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.name = 'nodes'; cb.value = 'vless:' + n.port; cb.checked = true;
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(n.seq_name + (n.protected ? '（保留）' : '')));
    list.appendChild(lab);
  });
  HY2.forEach(h => {
    any = true;
    const lab = document.createElement('label');
    lab.className = 'node-check-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.name = 'nodes'; cb.value = 'hy2:' + h.id; cb.checked = true;
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(h.seq_name + (h.protected ? '（保留）' : '')));
    list.appendChild(lab);
  });
  if (!any) { list.innerHTML = '<div class="badge-flow">没有可用节点</div>'; $('au-hint').textContent = ''; }
  $('addUserModal').classList.add('open');
}
function vlGroup(){
  const sec = $('vl-security').value, netEl = $('vl-network');
  let net = netEl.value;
  if (sec === 'reality' && net === 'ws') {
    net = 'tcp'; netEl.value = net;
  }
  if (vlAddMode) {
    $('vl-dest-row').classList.add('hidden');
    $('vl-keys').classList.add('hidden');
    $('vl-wspath-row').classList.add('hidden');
    $('vl-grpc-row').classList.add('hidden');
    return;
  }
  $('vl-dest-row').classList.toggle('hidden', sec !== 'reality');
  $('vl-keys').classList.toggle('hidden', sec !== 'reality');
  $('vl-wspath-row').classList.toggle('hidden', net !== 'ws');
  $('vl-grpc-row').classList.toggle('hidden', net !== 'grpc');
}
let vlAddMode = false;
async function genKeys(){
  try {
    const r = await fetch(APIBASE + 'gen_keys', { method: 'POST' });
    const d = await r.json();
    if (d.private && d.public) {
      $('vl-priv').value = d.private;
      $('vl-pub2').value = d.public;
      $('vl-pub').textContent = d.public;
    }
  } catch (e) {}
}
function openVlessModal(){
  const f = $('vlessForm');
  $('vlessModalTitle').textContent = '添加 vless 节点';
  f.action = APIBASE + 'inbound/add';
  $('vl-port').disabled = false;
  $('vl-remark').value = 'vless' + (NODES.length + 1);
  $('vl-port').value = '';
  $('vl-security').value = 'reality';
  $('vl-network').value = 'tcp';
  $('vl-sni').value = '';
  $('vl-dest').value = '';
  $('vl-wspath').value = '';
  $('vl-grpc').value = '';
  $('vl-priv').value = '';
  $('vl-pub').textContent = '（保存时自动生成）';
  vlAddMode = true;
  $('vl-security-row').classList.add('hidden');
  $('vl-network-row').classList.add('hidden');
  $('vl-port').value = randomOpenPort();
  const s = randomSite();
  $('vl-sni').value = s;
  $('vl-dest').value = s + ':443';
  vlGroup();
  $('vlessModal').classList.add('open');
}
function openHy2Modal(){
  const f = $('hy2Form');
  $('hy2ModalTitle').textContent = '添加 hy2 节点';
  f.action = APIBASE + 'hy2node/add';
  $('hy2-port').disabled = false;
  $('hy2-name').value = 'hy' + (HY2.length + 1);
  $('hy2-port').value = '';
  $('hy2-stats').value = '';
  $('hy2-masq').value = 'https://www.amazon.com';
  $('hy2-sni').value = '';
  $('hy2-masq-row').classList.add('hidden');
  $('hy2-stats-row').classList.add('hidden');
  $('hy2-cert-hint').classList.add('hidden');
  $('hy2-port').value = randomOpenPort();
  const s = randomSite();
  $('hy2-sni').value = s;
  $('hy2-masq').value = 'https://' + s;
  $('hy2Modal').classList.add('open');
}
function openFwdModal(){
  const f = $('fwdForm');
  $('fwdModalTitle').textContent = '添加中转';
  f.action = APIBASE + 'fwd/add';
  $('fwd-name').value = 'fwd' + (FWD.length + 1);
  $('fwd-port').value = randomOpenPort();
  $('fwd-tport').value = '';
  $('fwd-tip').value = '';
  $('fwdModal').classList.add('open');
}
function openHy2PassModal(name){
  $('hp-label').textContent = name;
  $('hp-pass').value = '';
  $('hy2PassForm').action = APIBASE + 'user/setpass/' + encodeURIComponent(name);
  $('hy2PassModal').classList.add('open');
}
function genUuidPass(){
  const c = (crypto && crypto.randomUUID) ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (cc) {
        const r = Math.random() * 16 | 0;
        return (cc === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
  $('hp-pass').value = c;
}
function copyText(txt, msg){
  function done(){ try { showToast(msg || '已复制', false); } catch (e) { alert(msg || '已复制'); } }
  function fb(){
    var ta = document.createElement('textarea');
    ta.value = txt; ta.style.position = 'fixed'; ta.style.top = '-1000px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta); done();
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(done).catch(fb);
    } else { fb(); }
  } catch (e) { fb(); }
}
async function exportUserYaml(name){
  try {
    const r = await fetch(APIBASE + 'user/export_yaml/' + encodeURIComponent(name), { method: 'POST' });
    if (!r.ok) { showToastErr('导出失败：' + (await r.text())); return; }
    const txt = await r.text();
    const cnt = txt.split(String.fromCharCode(10)).filter(l => l.trim().startsWith('- name:')).length;
    try { await navigator.clipboard.writeText(txt); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = txt; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
    }
    showToast('已复制 ' + name + ' 的节点配置（' + cnt + ' 个节点）到剪贴板', false);
  } catch (e) { showToastErr('导出失败：' + e); }
}
async function exportUserLink(name){
  try {
    const r = await fetch(APIBASE + 'user/export_link/' + encodeURIComponent(name), { method: 'POST' });
    if (!r.ok) { showToastErr('导出失败：' + (await r.text())); return; }
    const txt = await r.text();
    const cnt = (txt.match(/vless:\/\//g) || []).length + (txt.match(/hysteria2:\/\//g) || []).length;
    try { await navigator.clipboard.writeText(txt); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = txt; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
    }
    showToast('已复制 ' + name + ' 的节点链接（' + cnt + ' 条）到剪贴板', false);
  } catch (e) { showToastErr('导出失败：' + e); }
}
function openAddNodeModal(name){
  $('addNodeForm').reset();
  $('addNodeForm').action = APIBASE + 'user/add_node/' + encodeURIComponent(name);
  $('addNodeTitle').textContent = '为 ' + name + ' 管理节点';
  const used = new Set();
  const tr = document.querySelector('#clients-panel tr[data-cid="' + CSS.escape(name) + '"]');
  const bound = $('an-bound-list');
  bound.innerHTML = '';
  const trIsAdmin = tr && tr.dataset.admin === '1';
  if (tr) {
    tr.querySelectorAll('.node-chip').forEach(ch => {
      const kind = ch.dataset.kind, key = ch.dataset.key;
      used.add(kind + ':' + key);
      const label = ch.textContent.replace('×', '').trim();
      const item = document.createElement('div');
      item.className = 'an-bound-item';
      const lbl = document.createElement('span');
      lbl.className = 'lbl';
      const tag = document.createElement('span');
      tag.className = 'tag-' + (kind === 'hy2' ? 'hy2' : 'vless');
      tag.textContent = kind === 'hy2' ? 'hy2' : 'vless';
      const txt = document.createElement('span');
      txt.textContent = label;
      lbl.appendChild(tag); lbl.appendChild(txt);
      item.appendChild(lbl);
      const prot = trIsAdmin && ch.classList.contains('chip-protected');
      if (prot) {
        const badge = document.createElement('span');
        badge.className = 'tag-hy2';
        badge.textContent = '保留';
        item.appendChild(badge);
      } else {
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'unbind-btn';
        btn.textContent = '解绑';
        btn.onclick = () => {
          if (!confirm('把用户 ' + name + ' 从节点 ' + label + ' 解绑？')) return;
          btn.disabled = true; btn.textContent = '...';
          fetch(APIBASE + 'user/remove_node/' + encodeURIComponent(name) + '/' + kind + '/' + encodeURIComponent(key), { method: 'POST' })
            .then(() => location.reload())
            .catch(() => { btn.disabled = false; btn.textContent = '解绑'; showToastErr('解绑失败'); });
        };
        item.appendChild(btn);
      }
      bound.appendChild(item);
    });
  }
  if (!bound.children.length) { bound.innerHTML = '<div class="an-empty">该用户未绑定节点</div>'; }
  const list = $('an-node-list');
  list.innerHTML = '';
  NODES.forEach(n => {
    if (used.has('vless:' + n.port)) return;
    const lab = document.createElement('label');
    lab.className = 'node-check-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.name = 'nodes'; cb.value = 'vless:' + n.port; cb.checked = true;
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(n.seq_name + (n.protected ? '（保留）' : '')));
    list.appendChild(lab);
  });
  HY2.forEach(h => {
    if (used.has('hy2:' + h.id)) return;
    const lab = document.createElement('label');
    lab.className = 'node-check-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.name = 'nodes'; cb.value = 'hy2:' + h.id; cb.checked = true;
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(h.seq_name + (h.protected ? '（保留）' : '')));
    list.appendChild(lab);
  });
  if (!list.children.length) { list.innerHTML = '<div class="an-empty">没有可添加的节点</div>'; }
  $('addNodeModal').classList.add('open');
}
var _toastTimer = null;
var _toastEl = null;
function showToast(msg, isHtml){
  if (!_toastEl) {
    _toastEl = document.createElement('div');
    _toastEl.id = 'async-toast';
    document.body.appendChild(_toastEl);
  }
  if (isHtml) { _toastEl.innerHTML = msg; } else { _toastEl.textContent = msg; }
  _toastEl.classList.add('show');
  _toastEl.classList.remove('err');
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(function(){ if (_toastEl) _toastEl.classList.remove('show'); }, 2000);
}
function showToastErr(msg){
  showToast(msg, false);
  if (_toastEl) _toastEl.classList.add('err');
}
function updatePanel(d){
  if (!d || !d.html) return;
  const tmp = document.createElement('div');
  tmp.innerHTML = d.html;
  var src = tmp.querySelector('.wrap');
  var wrap = document.querySelector('.wrap');
  if (wrap && src) {
    wrap.innerHTML = src.innerHTML;
  }
  if (d.nodes) NODES = d.nodes;
  if (d.hy2) HY2 = d.hy2;
  if (d.fwd) FWD = d.fwd;
  loadFirewall();
}
function closeOpenModal(){
  var m = document.querySelector('.modal-backdrop.open');
  if (m) m.classList.remove('open');
}
function asyncPost(form){
  var action = form.getAttribute('action') || form.action;
  form.classList.add('busy');
  function doTry(triesLeft){
    fetch(action, { method: 'POST', credentials: 'same-origin', body: new FormData(form) })
      .then(function(resp){
        if (!resp.ok) {
          form.classList.remove('busy');
          if (resp.status === 502 || resp.status === 503 || resp.status === 504) {
            showToastErr('网关中断(' + resp.status + ')：操作可能已生效，请刷新页面确认');
          } else {
            showToastErr('请求失败（状态 ' + resp.status + '），请重试');
          }
          return;
        }
        resp.json().then(function(d){
          form.classList.remove('busy');
          closeOpenModal();
          if (!d || d.ok === false) {
            showToastErr((d && d.msg) || '操作失败');
            if (d && d.html) updatePanel(d);
            return;
          }
          updatePanel(d);
          showToast((d && d.msg) || '操作成功', true);
        }).catch(function(){
          if (triesLeft > 0) { setTimeout(function(){ doTry(triesLeft - 1); }, 600); return; }
          form.classList.remove('busy'); showToastErr('响应解析失败，请重试');
        });
      })
      .catch(function(){
        form.classList.remove('busy');
        if (triesLeft > 0) { setTimeout(function(){ doTry(triesLeft - 1); }, 600); return; }
        showToastErr('连接失败，操作未执行，请检查网络后重试');
      });
  }
  doTry(1);
}
document.addEventListener('submit', function(e){
  var form = e.target;
  if (!form || form.classList && !form.classList.contains('async-form')) return;
  if (form.dataset.confirm && !confirm(form.dataset.confirm)) { e.preventDefault(); return; }
  e.preventDefault();
  asyncPost(form);
});
// limit 总开关：事件委托（DOM 被 updatePanel 替换后仍有效）
document.addEventListener('change', function(e){
  var cb = e.target;
  if (!cb || cb.id !== 'limitToggle') return;
  var on = cb.checked;
  cb.disabled = true;
  var fd = new FormData(); fd.append('on', on ? '1' : '0');
  fetch(APIBASE + 'admin/limit_toggle', { method:'POST', credentials:'same-origin', body: fd })
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.ok) { location.reload(); }
      else { cb.disabled = false; cb.checked = !on; showToastErr((d && d.msg) || '操作失败'); }
    })
    .catch(function(){ cb.disabled = false; cb.checked = !on; showToastErr('网络错误'); });
});
function ackAllowlist(){
  var b = document.getElementById('allowlist-hint');
  fetch(APIBASE + 'panel_ack_allowlist', { method:'POST', credentials:'same-origin' })
    .then(function(r){ return r.json(); })
    .then(function(){ if(b){ b.style.display='none'; } showToast('已记录。可在『防火墙』卡片中放行你的 IP 并删除 Anywhere 规则', false); })
    .catch(function(){ if(b){ b.style.display='none'; } });
}
var FW = { ip: '', port: 0, off: false };
async function loadFirewall(){
  const box = $('fw-body');
  try {
    const r = await fetch(APIBASE + 'firewall/list', { method: 'POST' });
    const d = await r.json();
    if (!d.ok) { box.innerHTML = '<div class="empty-state">读取失败：' + d.msg + '</div>'; return; }
    FW.ip = d.current_ip || ''; FW.port = d.panel_port || 0; FW.off = d.ufw_off;
    setT('fw-count', FW.off ? '' : (d.rules || []).length);
    if (FW.off) { box.innerHTML = '<div class="empty-state">未检测到 ufw，防火墙管理不可用</div>'; return; }
    var rules = d.rules || [];
    var html = '<div style="padding:10px 20px;font-size:12px;color:#8a929e;border-bottom:1px solid #f2f4f6;">' +
      '当前访问 IP：<b class="mono">' + FW.ip + '</b> · 面板端口：<b>' + FW.port + '</b>' +
      '</div>';
    if (!rules.length) { html += '<div class="empty-state">暂无 ufw 规则</div>'; }
    else {
      html += '<table><tr><th>#</th><th>端口/协议</th><th>动作</th><th>来源</th><th>操作</th></tr>';
      rules.forEach(function(r){
        var mine = FW.ip && r.from && r.from.indexOf(FW.ip) !== -1;
        html += '<tr><td>' + r.num + '</td><td class="mono">' + r.to + '</td><td>' + r.action + (r.action === 'ALLOW' ? ' IN' : '') + '</td>' +
          '<td class="mono">' + r.from + (mine ? ' <span class="tag-hy2">当前IP</span>' : '') + '</td>' +
          '<td><button type="button" class="btn-sm-danger" onclick="fwDelete(' + r.num + ')">删除</button></td></tr>';
      });
      html += '</table>';
    }
    box.innerHTML = html;
  } catch (e) { box.innerHTML = '<div class="empty-state">读取失败：' + e + '</div>'; }
}
function fwPost(path, body, okMsg){
  fetch(APIBASE + path, { method: 'POST', credentials: 'same-origin', body: body })
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.ok) { showToast(okMsg, true); loadFirewall(); }
      else { showToastErr((d && d.msg) || '操作失败'); }
    })
    .catch(function(){ showToastErr('连接失败，请重试'); });
}
function fwAllowPort(){
  const p = $('fw-port').value;
  if (!p || !(Number(p) >= 1 && Number(p) <= 65535)) { showToastErr('请填写 1-65535 的端口'); return; }
  const fd = new FormData();
  fd.append('port', p); fd.append('proto', $('fw-proto').value);
  fwPost('firewall/allow', fd, '端口已放行');
}
function fwAllowIp(){
  const ip = $('fw-ip').value.trim(), p = $('fw-port').value;
  if (!ip) { showToastErr('请填写来源 IP'); return; }
  if (!p || !(Number(p) >= 1 && Number(p) <= 65535)) { showToastErr('请填写 1-65535 的端口'); return; }
  const fd = new FormData();
  fd.append('port', p); fd.append('proto', $('fw-proto').value); fd.append('ip', ip);
  fwPost('firewall/allow', fd, '已放行 ' + ip + ' → 端口 ' + p);
}
function allowMyIp(){
  if (!FW.port) { loadFirewall(); return; }
  if (!FW.ip) { showToastErr('未能获取当前 IP'); return; }
  const fd = new FormData();
  fd.append('port', FW.port); fd.append('proto', 'tcp'); fd.append('ip', FW.ip);
  fwPost('firewall/allow', fd, '已放行当前 IP 访问面板端口');
}
function fwDelete(n){
  if (!confirm('确定删除 ufw 规则 #' + n + '？\n若删除后当前 IP 将无法访问面板，操作会被系统拒绝。')) return;
  const fd = new FormData();
  fd.append('num', n);
  fwPost('firewall/delete', fd, '规则已删除');
}
if (typeof INIT_FLASH !== 'undefined' && INIT_FLASH) {
  if (INIT_FLASH.t === 'err') { showToastErr(INIT_FLASH.m); } else { showToast(INIT_FLASH.m, true); }
}

$('hy2PassForm').onsubmit = function(){ return true; };
$('addUserForm').onsubmit = function(){
  if (!$('au-name').value.trim()) return false;
  const nodes = Array.from(this.querySelectorAll('input[name="nodes"]:checked'));
  if (!nodes.length) { showToastErr('请至少选择一个节点'); return false; }
  this.action = APIBASE + 'user/add';
  return true;
};
$('addNodeForm').onsubmit = function(){
  const nodes = Array.from(this.querySelectorAll('input[name="nodes"]:checked'));
  if (!nodes.length) { showToastErr('请至少选择一个节点'); return false; }
  return true;
};
function fmtB(n){
  n = Number(n) || 0;
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + u[i];
}
function $(id){ return document.getElementById(id); }
function setT(id, txt){ const el = $(id); if (el && txt != null) el.textContent = txt; }
function setGauge(id, pct, txt){
  const el = $(id);
  if (!el) return;
  pct = Math.max(0, Math.min(100, Number(pct) || 0));
  el.style.setProperty('--p', pct.toFixed(2));
  el.style.setProperty('--c', pct < 80 ? '#67C23A' : (pct < 90 ? '#E6A23C' : '#F56C6C'));
  const s = el.querySelector('span');
  if (s && txt != null) s.textContent = txt;
}
async function pollStatus(){
  try {
    const r = await fetch(APIBASE + 'status', { method: 'POST' });
    const d = await r.json();
    setGauge('g-cpu', d.cpu, (Number(d.cpu) || 0).toFixed(1) + '%');
    setT('g-cpu-sub', (d.cpuNum || 0) + ' core');
    function pct(o){ return o && o.total ? (o.used / o.total * 100) : 0; }
    function comb(o){ return fmtB(o.used) + ' / ' + fmtB(o.total); }
    setGauge('g-mem', pct(d.mem), pct(d.mem).toFixed(1) + '%');   setT('g-mem-sub', comb(d.mem));
    setGauge('g-swap', pct(d.swap), pct(d.swap).toFixed(1) + '%'); setT('g-swap-sub', comb(d.swap));
    setGauge('g-disk', pct(d.disk), pct(d.disk).toFixed(1) + '%'); setT('g-disk-sub', comb(d.disk));
    const vs = d.xray || {};
    var xst = vs.running ? 'Running' : 'Stopped';
    if (!vs.running && svXrayWasRunning && Date.now() - svXrayWasRunning < 12000) xst = '重启中…';
    if (vs.running) svXrayWasRunning = Date.now();
    setT('sv-xray', xst + (vs.version ? ' · v' + vs.version : ''));
    const up = Number(d.uptime) || 0;
    const day = Math.floor(up / 86400), hr = Math.floor(up % 86400 / 3600), mi = Math.floor(up % 3600 / 60);
    setT('sv-uptime', (day ? day + ' 天 ' : '') + (hr ? hr + ' 小时 ' : '') + mi + ' 分');
    setT('sv-load', (d.loads || []).map(x => Number(x).toFixed(2)).join(' | '));
    setT('sv-tcp', d.tcpCount); setT('sv-udp', d.udpCount);
    setT('sv-net-up', fmtB(d.netIO.up) + '/s'); setT('sv-net-down', fmtB(d.netIO.down) + '/s');
    setT('sv-tot-up', fmtB(d.totTraffic.up));  setT('sv-tot-down', fmtB(d.totTraffic.down));
    setT('sv-nic-up', fmtB(d.netTraffic.sent)); setT('sv-nic-down', fmtB(d.netTraffic.recv));
    const now = new Date();
    const p2 = x => (x < 10 ? '0' : '') + x;
    setT('sv-tick', p2(now.getHours()) + ':' + p2(now.getMinutes()) + ':' + p2(now.getSeconds()));
  } catch (e) {}
}
async function restartXray(){
  if (!confirm('确定重启 xray 服务？')) return;
  const box = $('restart-msg');
  try {
    const r = await fetch(APIBASE + 'restart_xray', { method: 'POST' });
    if (!r.ok) {
      if (box) { box.style.display = ''; box.className = 'flash-msg err'; box.textContent = '重启请求失败（状态 ' + r.status + '），请刷新页面后重试'; }
      return;
    }
    let d = {};
    const txt = await r.text();
    try { d = JSON.parse(txt); } catch (e) {}
    if (box) { box.style.display = ''; box.className = 'flash-msg ' + (d.ok ? 'ok' : 'err'); box.textContent = d.ok ? '重启已触发，几秒后 xray 自动恢复' : ('重启失败：' + ((d && d.error) || '未知错误')); }
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'flash-msg err'; box.textContent = '连接中断：重启已触发，请稍后刷新确认 xray 状态'; }
  }
}
setInterval(pollStatus, 5000);
pollStatus();
loadFirewall();
</script>

</body></html>
"""

def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("panel.login"))
        last = session.get("last_activity", 0)
        if time.time() - last > 3600:
            session.clear()
            return redirect(url_for("panel.login"))
        session["last_activity"] = time.time()
        return f(*a, **kw)
    return wrapper

_prev_status = {"t": None, "busy": 0, "total": 0, "net": None}
_xray_ver_cache = {"t": 0, "v": None}
_xray_run_cache = {"t": 0, "v": None}

def _sys_uptime():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except Exception:
        return 0.0

def _cpu_jiffies():
    try:
        with open("/proc/stat") as f:
            parts = [int(x) for x in f.readline().split()[1:]]
        idle = parts[3] + parts[4] if len(parts) > 4 else 0
        return sum(parts), idle
    except Exception:
        return 0, 0

def _nic_bytes():
    out = {}
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
        for line in lines:
            name, data = line.split(":", 1)
            name = name.strip()
            if name == "lo":
                continue
            v = data.split()
            out[name] = (int(v[0]), int(v[8]))
    except Exception:
        pass
    return out

def _proc_count(path):
    try:
        with open(path) as f:
            return max(sum(1 for _ in f) - 1, 0)
    except Exception:
        return 0

def _xray_running():
    now = time.time()
    if _xray_run_cache["t"] and now - _xray_run_cache["t"] < 6:
        return _xray_run_cache["v"]
    try:
        r = subprocess.run(["systemctl", "is-active", XRAY_SERVICE_NAME],
                           capture_output=True, text=True, timeout=3)
        running = r.stdout.strip() == "active"
    except Exception:
        running = False
    _xray_run_cache["t"] = now
    _xray_run_cache["v"] = running
    return running

def _xray_version():
    now = time.time()
    if _xray_ver_cache["t"] and now - _xray_ver_cache["t"] < 300:
        return _xray_ver_cache["v"]
    ver = None
    try:
        r = subprocess.run(["/usr/local/bin/xray", "version"],
                           capture_output=True, text=True, timeout=4)
        head = (r.stdout or r.stderr).splitlines()[0]
        m = re.search(r"(\d+\.\d+\.\d+)", head)
        ver = m.group(1) if m else head.strip()
    except Exception:
        pass
    _xray_ver_cache["t"] = now
    _xray_ver_cache["v"] = ver
    return ver

def gather_status():
    """一次只读采样：CPU/内存/Swap/磁盘/负载/运行时长/连接数/速率/双口径总流量 + xray 真实状态。"""
    now = time.time()
    st = {
        "cpu": 0.0,
        "cpuNum": os.cpu_count() or 1,
        "mem": {"used": 0, "total": 0},
        "swap": {"used": 0, "total": 0},
        "disk": {"used": 0, "total": 0},
        "loads": [0.0, 0.0, 0.0],
        "uptime": 0.0,
        "tcpCount": 0,
        "udpCount": 0,
        "netIO": {"up": 0.0, "down": 0.0},
        "netTraffic": {"sent": 0, "recv": 0},
        "totTraffic": {"up": 0, "down": 0},
        "xray": {"running": _xray_running(), "version": _xray_version()},
    }

    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.strip().split()[0])
        mt = mem.get("MemTotal", 0)
        ma = mem.get("MemAvailable", mt)
        st["mem"] = {"used": max(mt - ma, 0) * 1024, "total": mt * 1024}
        sw_t = mem.get("SwapTotal", 0)
        sw_f = mem.get("SwapFree", sw_t)
        st["swap"] = {"used": max(sw_t - sw_f, 0) * 1024, "total": sw_t * 1024}
    except Exception:
        pass

    try:
        vfs = os.statvfs("/")
        total = vfs.f_blocks * vfs.f_frsize
        avail = vfs.f_bavail * vfs.f_frsize
        st["disk"] = {"used": max(total - avail, 0), "total": total}
    except Exception:
        pass

    try:
        with open("/proc/loadavg") as f:
            st["loads"] = [float(x) for x in f.read().split()[:3]]
    except Exception:
        pass
    st["uptime"] = _sys_uptime()
    st["tcpCount"] = _proc_count("/proc/net/tcp") + _proc_count("/proc/net/tcp6")
    st["udpCount"] = _proc_count("/proc/net/udp") + _proc_count("/proc/net/udp6")

    total, idle = _cpu_jiffies()
    busy = total - idle
    if _prev_status["t"] is not None:
        dt = now - _prev_status["t"]
        if dt > 0.001 and total >= _prev_status["total"] and total > _prev_status["total"]:
            db = busy - _prev_status["busy"]
            dtotal = total - _prev_status["total"]
            if dtotal > 0:
                st["cpu"] = max(0.0, min(100.0, db / dtotal * 100.0))

    nic = _nic_bytes()
    rx = sum(v[0] for v in nic.values())
    tx = sum(v[1] for v in nic.values())
    if _prev_status["net"] is not None:
        dt = now - _prev_status["t"]
        if dt > 0.001:
            st["netIO"]["up"] = max(0.0, (tx - _prev_status["net"]["tx"]) / dt)
            st["netIO"]["down"] = max(0.0, (rx - _prev_status["net"]["rx"]) / dt)
    st["netTraffic"]["sent"] = tx
    st["netTraffic"]["recv"] = rx

    _prev_status.update(t=now, busy=busy, total=total, net={"rx": rx, "tx": tx})

    tot = traffic_store.read_totals()
    st["totTraffic"]["up"] = sum(v.get("up", 0) for v in tot.values())
    st["totTraffic"]["down"] = sum(v.get("down", 0) for v in tot.values())
    return st

def human_bytes(n):
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def load_disabled():
    if not os.path.exists(DISABLED_PATH):
        return []
    try:
        with open(DISABLED_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def load_users():
    if not os.path.exists(USERS_PATH):
        return None
    try:
        with open(USERS_PATH) as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        return None
    return data

def save_users(data):
    atomic_write_json(USERS_PATH, data, chmod=0o644)

def migrate_users():
    """首次运行：从现有 xray config + disabled_clients + hy2_nodes 构建 users.json。
    合并规则：hy2 用户名去掉 _hy2/-hy2 后缀后若等于某 vless email，则并入该用户
    （该用户同时拿到两个协议的绑定），否则 hy2 用户独立成行。"""
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    real_nodes = real_node_inbounds(cfg.get("inbounds", []))
    users = {}
    order = []
    for _, ib in real_node_inbounds(cfg.get("inbounds", [])):
        port = ib.get("port")
        for c in ib.get("settings", {}).get("clients", []):
            cid = c.get("id")
            email = c.get("email") or cid
            rec = users.get(email)
            if rec is None:
                rec = {"name": email, "uuid": cid,
                       "flow": c.get("flow") or DEFAULT_FLOW,
                       "password": "", "hy2_name": "", "disabled": False,
                       "bindings": [{"proto": "vless", "node": port}]}
                users[email] = rec
                order.append(email)
                continue
            if not any(b["proto"] == "vless" and b["node"] == port for b in rec["bindings"]):
                rec["bindings"].append({"proto": "vless", "node": port})
    for c in load_disabled():
        cid = c.get("id")
        email = c.get("email") or cid
        rec = users.get(email)
        vless_ports = [{"proto": "vless", "node": ib.get("port")}
                       for _, ib in real_nodes if ib.get("port") is not None]
        if rec is None:
            rec = {"name": email, "uuid": cid,
                   "flow": c.get("flow") or DEFAULT_FLOW,
                   "password": "", "hy2_name": "", "disabled": True,
                   "bindings": [dict(b) for b in vless_ports]}
            users[email] = rec
            order.append(email)
        else:
            rec["disabled"] = True
    for h in load_hy2_nodes():
        hid = h.get("id")
        for u in h.get("users", []):
            uname = u.get("name")
            passwd = u.get("password", "")
            rec = users.get(uname)
            if rec is None:
                base = re.sub(r"[-_]hy2$", "", uname, flags=re.I)
                rec = users.get(base)
            if rec is None:
                rec = {"name": uname, "uuid": str(uuid.uuid4()),
                       "flow": DEFAULT_FLOW, "password": "", "hy2_name": uname,
                       "disabled": False, "bindings": []}
                users[uname] = rec
                order.append(uname)
            if not rec.get("password") and passwd:
                rec["password"] = passwd
            if not rec.get("hy2_name") and uname != rec.get("name"):
                rec["hy2_name"] = uname
            if not any(b["proto"] == "hy2" and b["node"] == hid for b in rec["bindings"]):
                rec["bindings"].append({"proto": "hy2", "node": hid})
    data = {"users": [users[n] for n in order]}
    save_users(data)
    return data

def get_users():
    data = load_users()
    if data is None:
        data = migrate_users()
    return data

def user_flow_raw(user, inbound):
    flow = user.get("flow") or DEFAULT_FLOW
    sec = (inbound.get("streamSettings") or {}).get("security")
    if sec and sec != "reality":
        flow = ""
    return flow

def rebuild_xray_from_users(cfg, users):
    """按 users.json 重建每个 vless 入站的 clients 列表（来源 truth=users）。"""
    for _, ib in real_node_inbounds(cfg.get("inbounds", [])):
        port = ib.get("port")
        clients = []
        for u in users:
            if u.get("disabled"):
                continue
            if not any(b["proto"] == "vless" and str(b["node"]) == str(port) for b in u.get("bindings", [])):
                continue
            clients.append({"id": u.get("uuid"), "email": u.get("name"),
                            "flow": user_flow_raw(u, ib)})
        ib.setdefault("settings", {})["clients"] = clients
    return cfg

def rebuild_hy2_users(nodes, users):
    """重建每个 hy2 节点的 users 列表（来源 truth=users）。返回（内容）变化的节点。"""
    touched = []
    for h in nodes:
        hid = h.get("id")
        new_users = []
        for u in users:
            if u.get("disabled"):
                continue
            if not any(b["proto"] == "hy2" and str(b["node"]) == str(hid) for b in u.get("bindings", [])):
                continue
            hname = u.get("hy2_name") or u.get("name")
            new_users.append({"name": hname, "password": u.get("password") or ""})
        old_users = [{"name": x.get("name"), "password": x.get("password")} for x in h.get("users", [])]
        if old_users != new_users:
            h["users"] = new_users
            touched.append(h)
    return touched

def _node_keys_from_form():
    """解析表单 nodes（value='vless:443' 或 'hy2:hy2-443'），去重。
    vless 的 node 归一化为 int 端口，hy2 保留字符串 id。"""
    out = []
    seen = set()
    for v in request.form.getlist("nodes"):
        if ":" not in v:
            continue
        p, k = v.split(":", 1)
        if p == "vless" and k.isdigit():
            k = int(k)
        key = (p, k)
        if key not in seen:
            seen.add(key)
            out.append({"proto": p, "node": k})
    return out

def _apply_user_change(users):
    """把 users 同步到 xray + hy2 配置。返回 (ok, err) 含两边的错误信息。"""
    data = {"users": users}
    save_users(data)
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    rebuild_xray_from_users(cfg, users)
    main_err = None
    ok, err = write_config_and_restart(cfg)
    if not ok:
        main_err = "xray 重启失败：%s" % err
    nodes = load_hy2_nodes()
    touched = rebuild_hy2_users(nodes, users)
    if nodes:
        save_hy2_nodes(nodes)
    for h in touched:
        ok2, err2 = apply_hy2_node(h)
        if not ok2:
            if main_err is None:
                main_err = "Hysteria2 节点 %s 服务重启失败：%s" % (h.get("name") or h.get("id"), err2)
            else:
                main_err += "；%s 服务重启失败：%s" % (h.get("name") or h.get("id"), err2)
    return ok, main_err

def _prune_user_bindings(users, proto, node):
    changed = False
    for u in users:
        bs = u.get("bindings", [])
        new_bs = [b for b in bs if not (b.get("proto") == proto and str(b.get("node")) == str(node))]
        if len(new_bs) != len(bs):
            u["bindings"] = new_bs
            changed = True
    return changed

def load_hy2_nodes():
    """v3 格式节点清单（面板可管）。容忍旧格式（无 stats/users 的纯展示条目）：
    每个旧条目视为一个节点，自动补 stats 只读展示，不可 apply。
    新格式字段：id/name/port/protocol/network/sni/dest/auth/enabled/cert/key/masquerade/stats{listen,secret}/users[{name,password}]"""
    if not os.path.exists(HY2_NODES_PATH):
        return []
    try:
        with open(HY2_NODES_PATH) as f:
            data = json.load(f)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            continue
        node = dict(raw)
        node.setdefault("id", "hy2-%d" % (i + 1))
        node.setdefault("name", node.get("name") or "")
        node.setdefault("port", node.get("port", 0))
        node.setdefault("protocol", node.get("protocol", "Hysteria2"))
        node.setdefault("network", node.get("network", "UDP"))
        node.setdefault("sni", node.get("sni", "-"))
        node.setdefault("dest", node.get("dest", "-"))
        node.setdefault("auth", node.get("auth", "-"))
        node.setdefault("enabled", True)
        node.setdefault("cert", node.get("cert") or TLS_CERT_FILE)
        node.setdefault("key", node.get("key") or TLS_KEY_FILE)
        node.setdefault("masquerade", node.get("masquerade", node.get("dest", "https://www.amazon.com")))
        stats = node.get("stats") or {}
        if not stats.get("listen"):
            try:
                stats_port = int(node.get("stats_port") or 10000)
                stats = {"listen": "%s:%d" % (HY2_STATS_HOST, stats_port),
                         "secret": node.get("stats_secret") or secrets.token_hex(16)}
            except Exception:
                stats = {"listen": "%s:9999" % HY2_STATS_HOST, "secret": secrets.token_hex(16)}
        node["stats"] = stats
        users = node.get("users")
        if not isinstance(users, list):
            users = [{"name": node.get("traffic_email") or "hy2-user", "password": node.get("auth_password") or ""}]
        node["users"] = [u for u in users if isinstance(u, dict)]
        out.append(node)
    return out

def save_hy2_nodes(nodes):
    atomic_write_json(HY2_NODES_PATH, nodes, chmod=0o644)

def load_disabled_inbounds():
    if not os.path.exists(DISABLED_INBOUNDS_PATH):
        return []
    try:
        with open(DISABLED_INBOUNDS_PATH) as f:
            data = json.load(f)
    except Exception:
        return []
    return data if isinstance(data, list) else []

def save_disabled_inbounds(items):
    atomic_write_json(DISABLED_INBOUNDS_PATH, items, chmod=0o644)

def _yaml_quote(s):
    return json.dumps(str(s), ensure_ascii=False)

def gen_uuid():
    try:
        r = subprocess.run([XRAY_BIN, "uuid"], capture_output=True, text=True, timeout=5)
        uid = (r.stdout or "").strip()
        if re.fullmatch(r"[0-9a-fA-F-]{36}", uid):
            return uid
    except Exception:
        pass
    return str(uuid.uuid4())

def find_xray():
    for p in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if os.path.exists(p):
            return p
    return "xray"

XRAY_BIN = find_xray()

def gen_reality_keys():
    r = subprocess.run([XRAY_BIN, "x25519"], capture_output=True, text=True, timeout=5)
    out = r.stdout or ""
    m1 = re.search(r"PrivateKey:\s*(\S+)", out)
    m2 = re.search(r"\(PublicKey\)[:\s]+(\S+)", out)
    if r.returncode != 0 or not m1 or not m2:
        raise RuntimeError("生成 REALITY 密钥失败：%s" % ((r.stderr or r.stdout or "xray x25519 无输出").strip()[:200]))
    return m1.group(1), m2.group(1)

def _reality_public_key(private_key):
    """由 REALITY 私钥派生公钥（xray x25519 -i）。失败返回空串。"""
    if not private_key:
        return ""
    try:
        r = subprocess.run([XRAY_BIN, "x25519", "-i", private_key],
                           capture_output=True, text=True, timeout=5)
        out = r.stdout or ""
        m = re.search(r"\(PublicKey\)[:\s]+(\S+)", out)
        if r.returncode == 0 and m:
            return m.group(1)
    except Exception:
        pass
    return ""

def render_hy2_yaml(node):
    """手写 YAML（不依赖 pyyaml）。auth 统一 userpass，可多用户。"""
    lines = ["listen: :%d" % int(node["port"]), ""]
    lines.append("tls:")
    lines.append("  cert: %s" % node["cert"])
    lines.append("  key: %s" % node["key"])
    lines.append("")
    lines.append("auth:")
    lines.append("  type: userpass")
    lines.append("  userpass:")
    for u in node.get("users", []):
        lines.append("    %s: %s" % (_yaml_quote(u.get("name", "")), _yaml_quote(u.get("password", ""))))
    lines.append("")
    lines.append("masquerade:")
    lines.append("  type: proxy")
    lines.append("  proxy:")
    lines.append("    url: %s" % _yaml_quote(node.get("masquerade", "https://www.amazon.com")))
    lines.append("    rewriteHost: true")
    lines.append("")
    lines.append("trafficStats:")
    lines.append("  listen: %s" % node["stats"]["listen"])
    lines.append("  secret: %s" % _yaml_quote(node["stats"]["secret"]))
    return "\n".join(lines) + "\n"

def write_hy2_unit_if_missing():
    if os.path.exists(HY2_UNIT_PATH):
        return
    unit = """[Unit]
Description=Hysteria2 Server Node (%i)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/conf.d/%i.yaml
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    tmp = HY2_UNIT_PATH + ".tmp"
    with open(tmp, "w") as f:
        f.write(unit)
    os.replace(tmp, HY2_UNIT_PATH)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=10)

def apply_hy2_node(node):
    """按节点状态写 conf.d/<id>.yaml 并启动/停止对应 hysteria-node@<id>.service。
    返回 (ok, err)。"""
    try:
        os.makedirs(HY2_CONF_DIR, exist_ok=True)
        write_hy2_unit_if_missing()
        unit = HY2_UNIT_NAME.format(id=node["id"])
        conf = os.path.join(HY2_CONF_DIR, node["id"] + ".yaml")
        if node.get("enabled"):
            with open(conf, "w") as f:
                f.write(render_hy2_yaml(node))
            os.chmod(conf, 0o644)
            subprocess.run(["systemctl", "enable", unit],
                           capture_output=True, timeout=15)
            r = subprocess.run(["systemctl", "restart", unit],
                               capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                return False, r.stderr.strip()
        else:
            subprocess.run(["systemctl", "disable", "--now", unit],
                           capture_output=True, text=True, timeout=20)
            if os.path.exists(conf):
                os.remove(conf)
        return True, None
    except Exception as e:
        return False, str(e)

def check_xray_port_conflict(cfg, port, exclude_port=None):
    for ib in cfg.get("inbounds", []):
        if ib.get("protocol", "").lower() in EXCLUDED_PROTOCOLS:
            continue
        if int(ib.get("port", 0)) == int(port) and int(port) != int(exclude_port or -1):
            return ib.get("port")
    return None

def check_hy2_port_conflict(nodes, port, exclude_id=None):
    for n in nodes:
        if n.get("id") == exclude_id:
            continue
        if int(n.get("port", 0)) == int(port):
            return n.get("port")
    return None

def load_fwd_rules():
    """中转规则清单。字段：id/name/listen_port/target_ip/target_port/tcp/udp/enabled/protected"""
    if not os.path.exists(FWD_RULES_PATH):
        return []
    try:
        with open(FWD_RULES_PATH) as f:
            data = json.load(f)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            continue
        r = dict(raw)
        r.setdefault("id", "fwd-%d" % (i + 1))
        r.setdefault("name", r.get("name") or ("fwd%d" % (i + 1)))
        r.setdefault("listen_port", r.get("listen_port", 0))
        r.setdefault("target_ip", r.get("target_ip", ""))
        r.setdefault("target_port", r.get("target_port", 0))
        r.setdefault("tcp", bool(r.get("tcp", True)))
        r.setdefault("udp", bool(r.get("udp", False)))
        r.setdefault("enabled", True)
        r.setdefault("protected", r.get("id") in PROTECTED_FWD_IDS)
        out.append(r)
    return out

def save_fwd_rules(rules):
    atomic_write_json(FWD_RULES_PATH, rules, chmod=0o644)

def _ufw_rules(port, action="allow"):
    """给端口放行/取消放行 ufw 的 tcp+udp 规则（无 ufw 环境静默跳过）。
    中端口是用户任意填的，deploy 只放行 22/443，所以必须动态放行，否则外网客户端被 ufw 拦截导致 timeout。"""
    if not shutil.which("ufw"):
        return
    try:
        for proto in ("tcp", "udp"):
            if action == "allow":
                subprocess.run(["ufw", "delete", "allow", "%d/%s" % (port, proto)],
                               capture_output=True, timeout=15)
                subprocess.run(["ufw", "allow", "%d/%s" % (port, proto)],
                               capture_output=True, timeout=15)
            else:
                subprocess.run(["ufw", "delete", "allow", "%d/%s" % (port, proto)],
                               capture_output=True, timeout=15)
    except Exception:
        pass

_def_panel_port = {"v": None}

def _panel_port():
    """探测面板自身监听端口：从 xray-viewer.service 的 ExecStart -b 里解析，
    失败回退 14325（dev 用法），结果缓存。"""
    if _def_panel_port["v"]:
        return _def_panel_port["v"]
    try:
        r = subprocess.run(["systemctl", "show", "xray-viewer", "-p", "ExecStart"],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"-b\s+[0-9.:]+:(\d+)", r.stdout or "")
        if m:
            _def_panel_port["v"] = int(m.group(1))
            return _def_panel_port["v"]
    except Exception:
        pass
    _def_panel_port["v"] = 14325
    return _def_panel_port["v"]

def _ufw_rules_list():
    """解析 `ufw status numbered` 输出。无 ufw 返回 None；失败抛异常。"""
    if not shutil.which("ufw"):
        return None
    try:
        r = subprocess.run(["ufw", "status", "numbered"], capture_output=True,
                           text=True, timeout=20)
    except Exception as e:
        raise RuntimeError("读取 ufw 规则失败：%s" % e)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip() or "ufw status 失败")
    rules = []
    for line in (r.stdout or "").splitlines():
        m = re.match(r"^\s*\[\s*(\d+)\]\s+(.+?)\s+(\S+)\s+(IN|OUT)\s+(.+?)\s*$", line)
        if not m:
            continue
        num, to, action, direction, src = m.group(1), m.group(2).strip(), m.group(3), m.group(4), m.group(5).strip()
        rules.append({"num": int(num), "to": to, "action": action,
                      "direction": direction, "from": src})
    return rules

def _ufw_run(args):
    """执行 ufw 子命令，非零退出抛异常。"""
    try:
        r = subprocess.run(["ufw"] + args, capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise RuntimeError("执行 ufw 失败：%s" % e)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip() or (r.stdout or "").strip() or "ufw 命令失败")
    return r.stdout or ""

def _rule_protects_panel(to, panel_port):
    parts = (to or "").split("/")
    if not parts or parts[0] != str(panel_port):
        return False
    if len(parts) == 1:
        return True
    return parts[1] == "tcp"

def _panel_rule_covers(rule, ip, panel_port):
    """该 ALLOW 规则是否覆盖指定 IP 访问面板端口。"""
    if (rule.get("action") or "").upper() != "ALLOW":
        return False
    if not _rule_protects_panel(rule.get("to", ""), panel_port):
        return False
    src = (rule.get("from") or "").strip()
    is_v6 = ":" in ip
    if src == "Anywhere (v6)" or src.startswith("Anywhere (v6) "):
        return is_v6
    if src == "Anywhere" or src.startswith("Anywhere "):
        return not is_v6
    return src == ip or src.startswith(ip + " ")

def _panel_access_after_delete(current_ip, panel_port, rules, delete_num):
    """模拟删除编号为 delete_num 的规则后，当前 IP 是否仍能访问面板。
    仅在【被删规则本身是当前 IP 访问面板的规则】且删除后无其他规则兜底时才拒绝。
    删除无关规则（如其它端口的 v6 镜像、未覆盖当前 IP 的规则）始终允许。"""
    ip = (current_ip or "").strip()
    target = next((r for r in rules if r.get("num") == delete_num), None)
    if target is None or not _panel_rule_covers(target, ip, panel_port):
        return True
    for r in rules:
        if r.get("num") == delete_num:
            continue
        if _panel_rule_covers(r, ip, panel_port):
            return True
    return False

def _fwd_tag(rule_id, proto):
    return "fwd-" + re.sub(r"[^A-Za-z0-9_.\@\-]", "-", str(rule_id)) + "-" + proto

def _fwd_dokodemo_inbounds(rules):
    """将启用的中转规则转成 xray dokodemo-door inbound（TCP/UDP 各自实例）。
    dokodemo-door 纯透明转发字节（兼具 NAT 保持源端口），适合 TCP 与 QUIC/UDP。"""
    out = []
    for r in rules:
        if not r.get("enabled"):
            continue
        lport, tip, tport = r["listen_port"], r.get("target_ip", ""), r["target_port"]
        if not (lport and tip and tport):
            continue
        for proto in ("tcp", "udp"):
            if (proto == "tcp" and r.get("tcp")) or (proto == "udp" and r.get("udp")):
                out.append({
                    "listen": "0.0.0.0",
                    "port": int(lport),
                    "protocol": "dokodemo-door",
                    "settings": {"address": tip, "port": int(tport), "network": proto},
                    "tag": _fwd_tag(r["id"], proto),
                })
    return out

def stamp_fwd_inbounds(cfg):
    """把 fwd 规则同步进 cfg 的 inbounds：先移除旧 fwd inbound，再按当前规则追加。"""
    inbounds = cfg.setdefault("inbounds", [])
    keep = [ib for ib in inbounds
            if not (ib.get("protocol") == "dokodemo-door" and str(ib.get("tag", "")).startswith("fwd-"))]
    keep.extend(_fwd_dokodemo_inbounds(load_fwd_rules()))
    cfg["inbounds"] = keep

def check_fwd_port_conflict(rules, port, exclude_id=None, cfg=None):
    if int(port) in PROTECTED_PORTS:
        return int(port)
    for r in rules:
        if r.get("id") == exclude_id:
            continue
        if int(r.get("listen_port", 0)) == int(port):
            return r.get("listen_port")
    if cfg is not None:
        for ib in cfg.get("inbounds", []):
            if ib.get("protocol", "").lower() in EXCLUDED_PROTOCOLS:
                continue
            if int(ib.get("port", 0)) == int(port):
                return ib.get("port")
    return None

def _find_fwd_rule(rule_id):
    rules = load_fwd_rules()
    for r in rules:
        if r.get("id") == rule_id:
            return rules, r
    return rules, None

def _apply_fwd_cfg(msg):
    """把当前 fwd 规则写入 xray config 并重启（dokodemo forwarding）。"""
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    ok, err = write_config_and_restart(cfg)
    if not ok:
        raise RuntimeError("xray 重启失败：%s" % err)
    session["flash_msg"] = msg
    session["flash_type"] = "ok"

def _stream_settings(form):
    security = form.get("security", "reality")
    network = form.get("network", "tcp")
    if security == "reality" and network not in ("tcp", "grpc", "xhttp"):
        raise RuntimeError("REALITY 不支持 WebSocket，请改选 TCP 或 gRPC")
    sni = (form.get("sni") or "www.amazon.com").strip()
    dest = (form.get("dest") or "").strip() or (sni + ":443")
    stream = {"network": network, "security": "none"}
    if security == "reality":
        priv, pub = gen_reality_keys()
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": True,
            "dest": dest,
            "xver": 0,
            "serverNames": [sni],
            "privateKey": priv,
            "shortIds": [secrets.token_hex(8)],
        }
        if pub:
            stream["ui_public_key"] = pub
    elif security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "alpn": ["h2", "http/1.1"],
            "certificates": [{"certificateFile": TLS_CERT_FILE, "keyFile": TLS_KEY_FILE}],
        }
    if network == "ws":
        stream["wsSettings"] = {"path": (form.get("ws_path") or "/").strip() or "/",
                                "headers": {"Host": sni}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": (form.get("grpc_service") or "vless").strip()}
    return stream

def vless_inbound_from_form(form, uid):
    port = int(form.get("port"))
    security = form.get("security", "reality")
    remark = (form.get("remark") or "").strip()
    inbound = {
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [],
            "decryption": "none",
        },
        "streamSettings": _stream_settings(form),
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        "tag": "inbound-%d" % port,
        "ui_remark": remark,
    }
    return inbound

def inbound_is_protected(port):
    return int(port) in PROTECTED_PORTS

# --- config write + debounced xray restart ---------------------------------
# Restarting xray on every UI action would be slow, so restarts are coalesced:
# the first caller claims a flag file and a worker restarts after a short
# debounce, while later callers just refresh the flag. config.json is written
# 0644 so the unprivileged xray process can read it.
def write_config_and_restart(cfg):
    stamp_fwd_inbounds(cfg)
    atomic_write_json(CONFIG_PATH, cfg, chmod=0o644)

    schedule_xray_restart()
    return True, None

_RESTART_FLAG = "/usr/local/etc/xray/.xray-restart.flag"
_RESTART_DEBOUNCE_SEC = 1.5
_RESTART_TOUCH_INTERVAL = 0.25
_restart_lock = threading.Lock()

def _try_claim_restart():
    """Atomically claim the restart flag. Returns True if this worker now
    owns the pending restart, False if another worker already claimed it."""
    try:
        fd = os.open(_RESTART_FLAG, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except Exception:
        return True

def _touch_restart_flag():
    """A mutation arrived while a claim already exists: bump the flag's
    mtime to extend the owner's debounce window so this write is folded
    into the same restart."""
    try:
        if os.path.exists(_RESTART_FLAG):
            os.utime(_RESTART_FLAG, None)
            return True
    except Exception:
        pass
    return False

def _release_restart():
    try:
        os.unlink(_RESTART_FLAG)
    except Exception:
        pass

def _do_xray_restart():
    try:
        traffic_store.accumulate_once()
    except Exception:
        pass
    try:
        subprocess.run(["systemctl", "restart", XRAY_SERVICE_NAME],
                       capture_output=True, timeout=30)
    except Exception:
        pass
    _release_restart()

def _deferred_restart_worker():
    try:
        last_seen = time.time()
        while True:
            time.sleep(_RESTART_TOUCH_INTERVAL)
            try:
                mtime = os.path.getmtime(_RESTART_FLAG)
            except FileNotFoundError:
                return
            except Exception:
                mtime = last_seen
            if mtime > last_seen:
                last_seen = mtime
            elif mtime + _RESTART_DEBOUNCE_SEC <= time.time():
                break
        try:
            with open(_RESTART_FLAG) as f:
                stamp = f.read().strip()
        except Exception:
            return
        if stamp != str(os.getpid()):
            return
        _do_xray_restart()
    except Exception:
        pass
    finally:
        if os.path.exists(_RESTART_FLAG):
            try:
                with open(_RESTART_FLAG) as f:
                    if f.read().strip() == str(os.getpid()):
                        _release_restart()
            except Exception:
                pass

def _read_flag_stamp():
    try:
        with open(_RESTART_FLAG) as f:
            return f.read().strip()
    except Exception:
        return None

def schedule_xray_restart():
    with _restart_lock:
        if _try_claim_restart():
            t = threading.Thread(target=_deferred_restart_worker, daemon=True)
            t.start()
            return
        stamp = _read_flag_stamp()
        owner_alive = False
        if stamp and stamp.isdigit():
            try:
                owner_alive = os.path.exists("/proc/%s" % stamp)
            except Exception:
                owner_alive = False
        if not owner_alive:
            try:
                os.unlink(_RESTART_FLAG)
                if _try_claim_restart():
                    t = threading.Thread(target=_deferred_restart_worker, daemon=True)
                    t.start()
                    return
            except Exception:
                pass
        else:
            _touch_restart_flag()

def is_real_node(inbound):
    return inbound.get("protocol", "").lower() not in EXCLUDED_PROTOCOLS

def real_node_inbounds(inbounds):
    return [(i, ib) for i, ib in enumerate(inbounds) if is_real_node(ib)]

def _login_lock_load():
    try:
        with open(LOGIN_LOCK_PATH) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    now = time.time()
    changed = False
    for k in list(data):
        rec = data[k]
        try:
            if isinstance(rec, dict) and (rec.get("locked_until") or 0) <= now and (rec.get("fails") or 0) < LOGIN_LOCK_FAIL_LIMIT:
                pass
        except Exception:
            data.pop(k, None)
            changed = True
    if not data:
        data = {}
    return data

def _login_lock_ctx():
    """跨 worker 互斥（gunicorn 2 进程共享文件锁）。非 Linux 环境降级为无锁。"""
    try:
        import fcntl
        lf = open(LOGIN_LOCK_PATH + ".lock", "w")
        fcntl.flock(lf, fcntl.LOCK_EX)
        return lf
    except Exception:
        return None

def _login_lock_mutate(fn):
    lf = _login_lock_ctx()
    try:
        return fn()
    finally:
        if lf is not None:
            try:
                lf.close()
            except Exception:
                pass

def _login_lock_left(ip, user):
    """剩余锁定秒数；未锁定返回 0。"""
    now = time.time()
    rec = _login_lock_load().get("%s|%s" % (ip, user))
    if not isinstance(rec, dict):
        return 0
    return max(0, int((rec.get("locked_until") or 0) - now))

def _login_lock_fail(ip, user):
    """记录一次失败；达到阈值写入锁定时间。返回当前剩余锁定秒数（0=未锁定）。"""
    now = time.time()
    key = "%s|%s" % (ip, user)
    def _do():
        data = _login_lock_load()
        rec = data.get(key)
        if not isinstance(rec, dict):
            rec = {"fails": 0, "locked_until": 0}
        if (rec.get("locked_until") or 0) <= now:
            rec["fails"] = (rec.get("fails") or 0) + 1
            if rec["fails"] >= LOGIN_LOCK_FAIL_LIMIT:
                rec["locked_until"] = now + LOGIN_LOCK_SECONDS
                rec["fails"] = 0
        data[key] = rec
        atomic_write_json(LOGIN_LOCK_PATH, data, keep=1)
        return rec
    return max(0, int(_login_lock_mutate(_do).get("locked_until") - now))

def _login_lock_clear(ip, user):
    """登录成功清除该组合的计数与锁定。"""
    key = "%s|%s" % (ip, user)
    def _do():
        data = _login_lock_load()
        if key in data:
            data.pop(key, None)
            atomic_write_json(LOGIN_LOCK_PATH, data, keep=1)
    _login_lock_mutate(_do)

def _fmt_lock_left(sec):
    sec = int(sec)
    h, m = divmod(sec, 3600)
    minutes = m // 60
    if h:
        return "%d 小时 %d 分钟" % (h, minutes)
    return "%d 分钟" % minutes

@panel.route("/login", methods=["GET", "POST"])
# Login is rate-limited per (IP, username): a few bad attempts lock the pair for
# a few hours. Credentials are verified against panel_auth.json (hashed).
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        user = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        left = _login_lock_left(ip, user)
        if left > 0:
            error = "该 IP 的账号 %s 已锁定，剩余 %s 自动解锁" % (user, _fmt_lock_left(left))
        else:
            au, ah = _auth()
            if user == au and _verify_pw(pw, ah):
                _login_lock_clear(ip, user)
                session["logged_in"] = True
                session.permanent = True
                session["last_activity"] = time.time()
                return redirect(url_for("panel.index"))
            left = _login_lock_fail(ip, user)
            if left > 0:
                error = ("密码错误已达 %d 次，该 IP 的账号 %s 已锁定 6 小时，"
                         "到时自动解锁" % (LOGIN_LOCK_FAIL_LIMIT, user))
            else:
                error = "用户名或密码错误"
    return render_template_string(LOGIN_HTML, error=error)

@panel.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("panel.login"))

@panel.route("/password", methods=["POST"])
@login_required
def change_password():
    try:
        old = request.form.get("old") or ""
        new = request.form.get("new") or ""
        au, ah = _auth()
        if not _verify_pw(old, ah):
            raise RuntimeError("原密码错误")
        if len(new) < 8:
            raise RuntimeError("新密码至少 8 位")
        _save_auth(au, _hash_pw(new))
        msg = "密码已更新"
    except Exception as e:
        return _panel_state("修改密码失败：%s" % e, False)
    return _panel_state(msg, True)

def _gen_unique_uid(users, exclude_name=None):
    """生成与其他所有用户 password 均不冲突的随机 UUID 值。"""
    used = {u.get("password") for u in users if u.get("name") != exclude_name and u.get("password")}
    while True:
        val = str(uuid.uuid4())
        if val not in used:
            return val

@panel.route("/user/add", methods=["POST"])
@login_required
def user_add():
    try:
        data = get_users()
        users = data["users"]
        name = (request.form.get("name") or "").strip()
        if not name:
            raise RuntimeError("名称不能为空")
        if any(u.get("name") == name for u in users):
            raise RuntimeError("用户 %s 已存在" % name)
        nodes = _node_keys_from_form()
        if not nodes:
            raise RuntimeError("请至少选择 1 个节点")
        uid = _gen_unique_uid(users)
        rec = {"name": name, "uuid": uid, "flow": DEFAULT_FLOW,
               "password": uid, "hy2_name": "", "disabled": False,
               "bindings": [{"proto": b["proto"], "node": b["node"]} for b in nodes]}
        users.append(rec)
        ok, err = _apply_user_change(users)
        parts = ["用户 <span class='mono'>%s</span> 已创建并绑定 %d 个节点"
                 % (name, len(nodes))]
        if any(b["proto"] == "vless" for b in nodes):
            parts.append("vless UUID：<span class='mono'>%s</span>" % rec["uuid"])
        if any(b["proto"] == "hy2" for b in nodes):
            parts.append("Hysteria2 密码：<span class='mono'>%s</span>" % rec["password"])
        if err:
            msg = "<br>".join(parts) + "（但 %s）" % err
            return _panel_state(msg, False)
        msg = "<br>".join(parts)
    except Exception as e:
        msg = "添加用户失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/add_node/<name>", methods=["POST"])
@login_required
def user_add_node(name):
    try:
        data = get_users()
        users = data["users"]
        rec = next((u for u in users if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        nodes = _node_keys_from_form()
        if not nodes:
            raise RuntimeError("请至少选择 1 个节点")
        existing = {(b.get("proto"), str(b.get("node"))) for b in rec.get("bindings", [])}
        added = 0
        for b in nodes:
            if (b["proto"], str(b["node"])) in existing:
                continue
            rec["bindings"].append({"proto": b["proto"], "node": b["node"]})
            added += 1
        if not added:
            raise RuntimeError("所选节点均已绑定")
        if any(b["proto"] == "hy2" for b in rec.get("bindings", [])) and not rec.get("password"):
            nuid = _gen_unique_uid(users, exclude_name=name)
            rec["uuid"] = nuid
            rec["password"] = nuid
        ok, err = _apply_user_change(users)
        label = rec["hy2_name"] or rec["name"]
        if err:
            msg = "已绑定 %d 个节点，但 %s" % (added, err)
            return _panel_state(msg, False)
        msg = "用户 <span class='mono'>%s</span> 已添加到 %d 个节点（hy2 用名 %s）" % (name, added, label)
    except Exception as e:
        msg = "添加节点失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/remove_node/<name>/<proto>/<node>", methods=["POST"])
@login_required
def user_remove_node(name, proto, node):
    try:
        data = get_users()
        users = data["users"]
        rec = next((u for u in users if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        is_admin = name in ADMIN_USERS
        if is_admin and proto == "vless" and inbound_is_protected(int(node)):
            raise RuntimeError("节点 %s 为系统保留，不允许移除 admin 的该绑定" % node)
        if is_admin and proto == "hy2" and node in PROTECTED_HY2_IDS:
            raise RuntimeError("节点 %s 为系统保留，不允许移除 admin 的该绑定" % node)
        before = len(rec.get("bindings", []))
        rec["bindings"] = [b for b in rec.get("bindings", [])
                           if not (b.get("proto") == proto and str(b.get("node")) == str(node))]
        if len(rec["bindings"]) == before:
            raise RuntimeError("该用户未绑定该节点")
        ok, err = _apply_user_change(users)
        if err:
            msg = "已移除绑定，但 %s" % err
            return _panel_state(msg, False)
        msg = "用户 <span class='mono'>%s</span> 已从节点 %s:%s 移除" % (name, proto, node)
    except Exception as e:
        msg = "移除失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/setpass/<name>", methods=["POST"])
@login_required
def user_setpass(name):
    try:
        data = get_users()
        users = data["users"]
        rec = next((u for u in users if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        newpass = request.form.get("newpass") or ""
        if not newpass:
            raise RuntimeError("新密码不能为空")
        clash = next((u.get("name") for u in users
                      if u.get("name") != name and u.get("password") == newpass), None)
        if clash:
            raise RuntimeError("该密码已被用户 %s 使用，每个用户密码必须唯一" % clash)
        rec["password"] = newpass
        if any(b.get("proto") == "vless" for b in rec.get("bindings", [])):
            rec["uuid"] = newpass
        ok, err = _apply_user_change(users)
        if err:
            msg = "密码已保存，但 %s" % err
            return _panel_state(msg, False)
        msg = ("用户 <span class='mono'>%s</span> 的 Hysteria2 密码已在全部节点更新" % name
               + ("；vless uuid 已同步为新密码" if rec["uuid"] == newpass else ""))
    except Exception as e:
        msg = "修改密码失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/toggle/<name>", methods=["POST"])
@login_required
def user_toggle(name):
    try:
        data = get_users()
        users = data["users"]
        rec = next((u for u in users if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        paused = not rec.get("disabled")
        rec["disabled"] = paused
        ok, err = _apply_user_change(users)
        state = "已在全部节点暂停" if paused else "已在全部节点恢复"
        if err:
            return _panel_state("状态已更改，但 %s" % err, False)
        msg = "用户 <span class='mono'>%s</span> %s" % (name, state)
    except Exception as e:
        msg = "操作失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/reset_traffic/<name>", methods=["POST"])
@login_required
def user_reset_traffic(name):
    try:
        data = get_users()
        rec = next((u for u in data["users"] if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        traffic_store.reset_entry(name)
        hname = rec.get("hy2_name")
        if hname and hname != name:
            traffic_store.reset_entry(hname)
        msg = "用户 <span class='mono'>%s</span> 的流量统计已清零" % name
    except Exception as e:
        msg = "重置失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/user/delete/<name>", methods=["POST"])
@login_required
def user_delete(name):
    try:
        data = get_users()
        users = data["users"]
        rec = next((u for u in users if u.get("name") == name), None)
        if rec is None:
            raise RuntimeError("未找到用户 %s" % name)
        users.remove(rec)
        ok, err = _apply_user_change(users)
        traffic_store.remove_entry(name)
        hname = rec.get("hy2_name")
        if hname and hname != name:
            traffic_store.remove_entry(hname)
        if err:
            return _panel_state("已删除用户，但 %s" % err, False)
        msg = "用户 <span class='mono'>%s</span> 已从全部节点删除" % name
    except Exception as e:
        msg = "删除失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

def _yaml_scalar(s):
    s = str(s)
    if s == "" or s != s.strip() or re.search(r"[:#\[\]\{\},&\*!|>'\"%@`]", s):
        return json.dumps(s, ensure_ascii=False)
    return s

@panel.route("/user/export_yaml/<name>", methods=["POST"])
@login_required
def user_export_yaml(name):
    """导出该用户名下所有启用节点（直连落地机地址）为 mihomo/Clash proxies YAML。"""
    try:
        data = get_users()
        rec = next((u for u in data["users"] if u.get("name") == name), None)
        if rec is None:
            return ("未找到用户", 404)
        if rec.get("disabled"):
            return ("用户 %s 已暂停，无可导出节点" % name, 400)
        proxies = [y for y, _ in _user_proxy_entries(rec)]
        if not proxies:
            return ("用户 %s 没有启用的可导出节点" % name, 400)

        lines = ["proxies:"]
        for p in proxies:
            lines.append("  - name: %s" % _yaml_scalar(p["name"]))
            for k, v in p.items():
                if k == "name":
                    continue
                if isinstance(v, dict):
                    lines.append("    %s:" % k)
                    for k2, v2 in v.items():
                        lines.append("      %s: %s" % (k2, _yaml_scalar(v2)))
                elif isinstance(v, bool):
                    lines.append("    %s: %s" % (k, "true" if v else "false"))
                elif isinstance(v, int):
                    lines.append("    %s: %d" % (k, v))
                else:
                    lines.append("    %s: %s" % (k, _yaml_scalar(v)))
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        return ("导出失败：%s" % e, 500)

def _proxy_link(e):
    if e.get("type") == "hysteria2":
        frag = quote(str(e.get("name") or "hysteria2"), safe="")
        q = []
        if e.get("sni"):
            q.append("sni=%s" % quote(str(e["sni"]), safe=""))
        q.append("insecure=1")
        return "hysteria2://%s:%s@%s:%s?%s#%s" % (
            quote(str(e.get("user", "")), safe=""),
            quote(str(e.get("pass", "")), safe=""),
            e.get("server", ""), e.get("port", ""), "&".join(q), frag)
    q = [("encryption", "none")]
    if e.get("flow"):
        q.append(("flow", e["flow"]))
    sec = e.get("security") or ""
    net = e.get("network") or "tcp"
    if net == "grpc":
        q.append(("type", "grpc"))
        q.append(("serviceName", e.get("grpc_service") or "vless"))
    elif net == "xhttp":
        q.append(("type", "xhttp"))
        if e.get("ws_path"):
            q.append(("path", e["ws_path"]))
        if e.get("sni"):
            q.append(("host", e["sni"]))
    elif net == "ws":
        q.append(("type", "ws"))
        if e.get("ws_path"):
            q.append(("path", e["ws_path"]))
        if e.get("sni"):
            q.append(("host", e["sni"]))
    else:
        q.append(("type", "tcp"))
    if sec == "reality":
        q.append(("security", "reality"))
        if e.get("sni"):
            q.append(("sni", e["sni"]))
        q.append(("fp", "chrome"))
        if e.get("pub"):
            q.append(("pbk", e["pub"]))
        if e.get("sid"):
            q.append(("sid", e["sid"]))
    elif sec == "tls":
        q.append(("security", "tls"))
        q.append(("fp", "chrome"))
        if e.get("sni"):
            q.append(("sni", e["sni"]))
    qs = "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in q)
    frag = quote(str(e.get("name") or "vless"), safe="")
    return "vless://%s@%s:%s?%s#%s" % (e.get("uuid", ""), e.get("server", ""),
                                       e.get("port", ""), qs, frag)

def _user_proxy_entries(rec):
    """收集用户可用节点描述。返回 [(yaml代理dict, 链接参数dict), ...]。
    yaml dict 字段与 v14 完全一致以保证 mihomo 输出逐字节不变。"""
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    disabled_inb = load_disabled_inbounds()
    paused_ports = {d.get("port") for d in disabled_inb}
    hy2_nodes_raw = load_hy2_nodes()
    hy2_by_id = {h.get("id"): h for h in hy2_nodes_raw}
    ADDR = _server_addr()
    entries = []
    name = rec.get("name") or ""
    # Build the same node display names the panel shows, so that the exported
    # link / YAML / QR carry the same name as the node list (not the user name).
    _real = real_node_inbounds(cfg.get("inbounds", []))
    _dvless = [x for x in disabled_inb if is_real_node(x) and x.get("protocol", "").lower() == "vless"]
    _vless_ports = sorted([x.get("port") for _, x in _real if x.get("protocol") == "vless"]
                          + [x.get("port") for x in _dvless])
    _vless_rank = {p: i + 1 for i, p in enumerate(_vless_ports)}
    _hy2_idx = {h.get("id"): i + 1 for i, h in enumerate(hy2_nodes_raw)}

    for b in rec.get("bindings", []):
        if b.get("proto") == "vless":
            port = b.get("node")
            if int(port) in paused_ports:
                continue
            ib = next((x for x in cfg.get("inbounds", [])
                       if x.get("protocol") in VLESS_PROTOCOLS and int(x.get("port", 0)) == int(port)), None)
            if ib is None:
                continue
            stream = ib.get("streamSettings", {}) or {}
            reality = stream.get("realitySettings") or {}
            sec = stream.get("security")
            network_raw = stream.get("network") or "tcp"
            ws_path = (stream.get("wsSettings") or {}).get("path", "") or "/"
            grpc_service = (stream.get("grpcSettings") or {}).get("serviceName", "") or "vless"
            server_name = (reality.get("serverNames") or [""])[0] or ""
            flow = user_flow_raw(rec, ib)
            pub = _reality_public_key(reality.get("privateKey", ""))
            if not pub:
                pub = stream.get("ui_public_key", "") or ""
            short_id = (reality.get("shortIds") or [""])[0] or ""
            uid = rec.get("uuid", "")
            vname = (ib.get("ui_remark") or "").strip() or ("vless%d" % _vless_rank.get(int(port), 0))
            if sec == "reality":
                p = {
                    "name": vname,
                    "type": "vless",
                    "server": ADDR,
                    "port": int(port),
                    "uuid": uid,
                    "network": network_raw,
                    "udp": True,
                    "tls": True,
                    "servername": server_name,
                    "client-fingerprint": "chrome",
                }
                if flow:
                    p["flow"] = flow
                p["reality-opts"] = {
                    "public-key": pub,
                    "short-id": short_id,
                }
            else:
                p = {
                    "name": vname,
                    "type": "vless",
                    "server": ADDR,
                    "port": int(port),
                    "uuid": uid,
                    "network": network_raw,
                    "udp": True,
                    "tls": True if sec == "tls" else False,
                }
            entries.append((p, {
                "name": vname, "type": "vless", "server": ADDR,
                "port": int(port), "uuid": uid, "network": network_raw,
                "security": sec or "", "flow": flow, "sni": server_name,
                "pub": pub, "sid": short_id,
                "ws_path": ws_path, "grpc_service": grpc_service,
            }))
        elif b.get("proto") == "hy2":
            h = hy2_by_id.get(str(b.get("node")))
            if h is None or not h.get("enabled", True):
                continue
            hname = rec.get("hy2_name") or rec.get("name") or name
            pw = rec.get("password", "") or ""
            hnode = h.get("name") or ("hy%d" % _hy2_idx.get(h.get("id"), 0))
            p = {
                "name": hnode,
                "type": "hysteria2",
                "server": ADDR,
                "port": int(h.get("port")),
                "password": "%s:%s" % (hname, pw),
                "sni": h.get("sni", "") or "",
                "skip-cert-verify": True,
            }
            entries.append((p, {
                "name": hnode, "type": "hysteria2", "server": ADDR,
                "port": int(h.get("port")), "user": hname, "pass": pw,
                "sni": h.get("sni", "") or "",
            }))
    return entries

@panel.route("/user/export_link/<name>", methods=["POST"])
@login_required
def user_export_link(name):
    """导出该用户名下所有启用节点为客户端标准分享链接（vless:// / hysteria2://）。"""
    try:
        data = get_users()
        rec = next((u for u in data["users"] if u.get("name") == name), None)
        if rec is None:
            return ("未找到用户", 404)
        if rec.get("disabled"):
            return ("用户 %s 已暂停，无可导出链接" % name, 400)
        links = [_proxy_link(e) for _, e in _user_proxy_entries(rec)]
        if not links:
            return ("用户 %s 没有启用的可导出节点" % name, 400)
        return "\n".join(links) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as e:
        return ("导出失败：%s" % e, 500)

@panel.route("/gen_keys", methods=["POST"])
@login_required
def gen_keys():
    priv, pub = gen_reality_keys()
    return jsonify({"private": priv, "public": pub})

@panel.route("/inbound/add", methods=["POST"])
@login_required
def inbound_add():
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        port = int(request.form.get("port"))
        if not 1 <= port <= 65535:
            raise RuntimeError("端口必须在 1-65535")
        if inbound_is_protected(port):
            raise RuntimeError("端口 %d 为系统保留（主节点 / xray api）" % port)
        if check_xray_port_conflict(cfg, port):
            raise RuntimeError("端口 %d 已有同协议入站" % port)
        remark = (request.form.get("remark") or "").strip()
        if remark and any(
            ((ib.get("ui_remark") or "").strip() == remark)
            for ib in cfg.get("inbounds", [])
            if ib.get("protocol") == "vless"
        ):
            raise RuntimeError("已有同名 vless 节点：%s" % remark)

        uid = gen_uuid()
        inbound = vless_inbound_from_form(request.form, uid)
        rs = inbound["streamSettings"].get("realitySettings")
        if rs and request.form.get("reality_private"):
            rs["privateKey"] = request.form["reality_private"].strip()
            if request.form.get("reality_public"):
                inbound["streamSettings"]["ui_public_key"] = request.form["reality_public"].strip()

        cfg.setdefault("inbounds", []).append(inbound)
        ok, err = write_config_and_restart(cfg)
        if not ok:
            raise RuntimeError("配置已写入但 xray 未启动：%s" % err)
        msg = (
            "已添加 vless 入站 :%d<br>客户端在「用户」面板中绑定"
            % port
        )
    except Exception as e:
        msg = "添加入站失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/inbound/delete/<int:port>", methods=["POST"])
@login_required
def inbound_delete(port):
    try:
        if inbound_is_protected(port):
            raise RuntimeError("端口 %d 为系统保留，不可删除" % port)
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        inbounds = cfg.get("inbounds", [])
        idx = next((i for i, ib in enumerate(inbounds)
                    if ib.get("port") == port), None)
        removed = inbounds.pop(idx) if idx is not None else None

        disabled = load_disabled_inbounds()
        d_idx = next((i for i, d in enumerate(disabled)
                      if d.get("port") == port), None)
        if d_idx is not None:
            disabled.pop(d_idx)
            save_disabled_inbounds(disabled)

        removed_both = None
        if removed is not None:
            removed_both = removed
        elif d_idx is not None:
            removed_both = None

        if removed is not None:
            ok, err = write_config_and_restart(cfg)
            if not ok:
                raise RuntimeError("配置已写入但 xray 未启动：%s" % err)
            data = load_users()
            if data is not None:
                if _prune_user_bindings(data["users"], "vless", port):
                    save_users(data)
        msg = "入站 :%d 已删除%s" % (
            port, ("（含其客户端）" if removed is not None else "（已暂停条目）"))
    except Exception as e:
        msg = "删除入站失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/inbound/toggle/<int:port>", methods=["POST"])
@login_required
def inbound_toggle(port):
    try:
        if inbound_is_protected(port):
            raise RuntimeError("端口 %d 为系统保留，不可暂停" % port)
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        inbounds = cfg.get("inbounds", [])
        disabled = load_disabled_inbounds()

        idx = next((i for i, ib in enumerate(inbounds)
                    if ib.get("port") == port), None)
        if idx is not None:
            inbound = inbounds.pop(idx)
            disabled.append(inbound)
            ok, err = write_config_and_restart(cfg)
            if ok:
                save_disabled_inbounds(disabled)
                msg = "入站 :%d 已暂停，可随时恢复" % port
            else:
                msg = "暂停失败，xray 重启出错：%s" % err
                return _panel_state(msg, False)
        else:
            d_idx = next((i for i, d in enumerate(disabled)
                          if d.get("port") == port), None)
            if d_idx is None:
                raise RuntimeError("未找到该入站 :%d" % port)
            inbound = disabled.pop(d_idx)
            inbounds.append(inbound)
            ok, err = write_config_and_restart(cfg)
            if ok:
                save_disabled_inbounds(disabled)
                msg = "入站 :%d 已恢复运行" % port
            else:
                msg = "恢复失败，xray 重启出错：%s" % err
                return _panel_state(msg, False)
    except Exception as e:
        msg = "操作失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

def _find_hy2_node(node_id):
    nodes = load_hy2_nodes()
    node = next((n for n in nodes if n.get("id") == node_id), None)
    return nodes, node

def _flash_save_apply(nodes, node, ok_msg):
    save_hy2_nodes(nodes)
    ok, err = apply_hy2_node(node)
    if ok:
        return ok_msg, True
    return "%s 已保存，但服务未启动：%s" % (ok_msg, err), False

@panel.route("/hy2node/add", methods=["POST"])
@login_required
def hy2node_add():
    try:
        name = (request.form.get("name") or "").strip()
        if not name:
            raise RuntimeError("请填写节点名称")
        port = int(request.form.get("port"))
        if not 1 <= port <= 65535:
            raise RuntimeError("端口必须在 1-65535")
        if check_hy2_port_conflict(load_hy2_nodes(), port):
            raise RuntimeError("端口 %d 已被其他 Hysteria2 节点占用" % port)
        if any((n.get("name") or "").strip() == name for n in load_hy2_nodes()):
            raise RuntimeError("已有同名 Hysteria2 节点：%s" % name)

        masq = (request.form.get("masquerade") or "").strip()
        sni = (request.form.get("sni") or "").strip()
        if masq and not sni:
            m = re.match(r"https?://([^/:]+)", masq)
            sni = m.group(1) if m else "www.amazon.com"
        if not masq:
            masq = ("https://" + sni) if sni else "https://www.amazon.com"
        if not sni:
            sni = "www.amazon.com"

        stats_port = request.form.get("stats_port")
        if stats_port:
            stats_port = int(stats_port)
        else:
            nodes_now = load_hy2_nodes()
            used = [int((n.get("stats") or {}).get("listen", "127.0.0.1:0").rsplit(":", 1)[-1] or 0)
                    for n in nodes_now]
            stats_port = max(used + [10000]) + 1

        node = {
            "id": "hy2-%d" % port,
            "name": name,
            "port": port,
            "protocol": "Hysteria2",
            "network": "UDP",
            "sni": sni,
            "dest": "%s:443" % sni,
            "auth": "信任自签证书",
            "enabled": True,
            "cert": TLS_CERT_FILE,
            "key": TLS_KEY_FILE,
            "masquerade": masq,
            "stats": {"listen": "%s:%d" % (HY2_STATS_HOST, stats_port),
                      "secret": secrets.token_hex(16)},
            "users": [],
        }
        nodes = load_hy2_nodes()
        nodes.append(node)
        save_hy2_nodes(nodes)
        msg = "Hysteria2 节点 %s (:UDP/%d) 已保存，请在列表「用户」栏添加第一个用户（添加时自动启动服务）" % (name, port)
    except Exception as e:
        msg = "添加节点失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/hy2node/delete/<node_id>", methods=["POST"])
@login_required
def hy2node_delete(node_id):
    try:
        if node_id in PROTECTED_HY2_IDS:
            raise RuntimeError("主节点 %s 不可删除" % node_id)
        nodes, node = _find_hy2_node(node_id)
        if node is None:
            raise RuntimeError("未找到该节点")
        nodes.remove(node)
        save_hy2_nodes(nodes)
        node = dict(node)
        node["enabled"] = False
        apply_hy2_node(node)
        data = load_users()
        if data is not None:
            if _prune_user_bindings(data["users"], "hy2", node_id):
                save_users(data)
        msg = "Hysteria2 节点 %s 已删除" % (node.get("name") or node.get("id"))
    except Exception as e:
        msg = "删除节点失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/hy2node/toggle/<node_id>", methods=["POST"])
@login_required
def hy2node_toggle(node_id):
    try:
        if node_id in PROTECTED_HY2_IDS:
            raise RuntimeError("主节点 %s 不可停止" % node_id)
        nodes, node = _find_hy2_node(node_id)
        if node is None:
            raise RuntimeError("未找到该节点")
        node["enabled"] = not node.get("enabled", True)
        msg, ok = _flash_save_apply(nodes, node,
                                    "Hysteria2 节点 %s 已%s" % (node.get("name") or node.get("id"),
                                                              "启动" if node["enabled"] else "停止"))
        return _panel_state(msg, ok)
    except Exception as e:
        return _panel_state("操作失败：%s" % e, False)

@panel.route("/fwd/add", methods=["POST"])
@login_required
def fwd_add():
    try:
        name = (request.form.get("name") or "").strip()
        listen_port = request.form.get("port")
        target_ip = (request.form.get("target_ip") or "").strip()
        target_port = request.form.get("target_port")
        tcp = True
        udp = True
        if not name:
            raise RuntimeError("请填写名称")
        if not (listen_port and target_ip and target_port):
            raise RuntimeError("本机端口、目标 IP、目标端口均必填")
        listen_port = int(listen_port)
        target_port = int(target_port)
        if not 1 <= listen_port <= 65535 or not 1 <= target_port <= 65535:
            raise RuntimeError("端口必须在 1-65535")
        with open(CONFIG_PATH) as f:
            cfg_now = json.load(f)
        if check_fwd_port_conflict(load_fwd_rules(), listen_port, cfg=cfg_now):
            raise RuntimeError("本机端口 %d 已被保护端口或其他中转占用" % listen_port)
        if any((r.get("name") or "").strip() == name for r in load_fwd_rules()):
            raise RuntimeError("已有同名中转节点：%s" % name)
        rule = {
            "id": "fwd-%d" % listen_port,
            "name": name,
            "listen_port": listen_port,
            "target_ip": target_ip,
            "target_port": target_port,
            "tcp": tcp,
            "udp": udp,
            "enabled": True,
            "protected": False,
        }
        rules = load_fwd_rules()
        rules.append(rule)
        save_fwd_rules(rules)
        _ufw_rules(listen_port, "allow")
        _apply_fwd_cfg("中转 %s (本机 :%d → %s:%d) 已启动" % (name, listen_port, target_ip, target_port))
        msg = "中转 %s (本机 :%d → %s:%d) 已启动" % (name, listen_port, target_ip, target_port)
    except Exception as e:
        msg = "添加中转失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/fwd/toggle/<rule_id>", methods=["POST"])
@login_required
def fwd_toggle(rule_id):
    try:
        if rule_id in PROTECTED_FWD_IDS:
            raise RuntimeError("该中转不可停止")
        rules, r = _find_fwd_rule(rule_id)
        if r is None:
            raise RuntimeError("未找到该中转")
        r["enabled"] = not r.get("enabled", True)
        save_fwd_rules(rules)
        _ufw_rules(r["listen_port"], "allow" if r["enabled"] else "deny")
        _apply_fwd_cfg("中转 %s 已%s" % (r.get("name"), "启动" if r["enabled"] else "停止"))
        msg = "中转 %s 已%s" % (r.get("name"), "启动" if r["enabled"] else "停止")
    except Exception as e:
        msg = "操作失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/fwd/delete/<rule_id>", methods=["POST"])
@login_required
def fwd_delete(rule_id):
    try:
        if rule_id in PROTECTED_FWD_IDS:
            raise RuntimeError("该中转不可删除")
        rules, r = _find_fwd_rule(rule_id)
        if r is None:
            raise RuntimeError("未找到该中转")
        rules.remove(r)
        save_fwd_rules(rules)
        _ufw_rules(r["listen_port"], "deny")
        _apply_fwd_cfg("中转 %s 已删除" % r.get("name"))
        msg = "中转 %s 已删除" % r.get("name")
    except Exception as e:
        msg = "删除中转失败：%s" % e
        return _panel_state(msg, False)
    return _panel_state(msg, True)

@panel.route("/firewall/list", methods=["POST"])
@login_required
def firewall_list():
    try:
        rules = _ufw_rules_list()
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})
    if rules is None:
        return jsonify({"ok": True, "ufw_off": True, "msg": "未检测到 ufw",
                        "rules": [], "current_ip": "", "panel_port": 0})
    return jsonify({"ok": True, "ufw_off": False, "rules": rules,
                    "current_ip": request.remote_addr or "",
                    "panel_port": _panel_port()})

@panel.route("/firewall/allow", methods=["POST"])
@login_required
def firewall_allow():
    try:
        port = (request.form.get("port") or "").strip()
        proto = (request.form.get("proto") or "tcp").strip().lower()
        ip = (request.form.get("ip") or "").strip()
        if not port:
            raise RuntimeError("请填写端口")
        port = int(port)
        if not 1 <= port <= 65535:
            raise RuntimeError("端口必须在 1-65535")
        args = ["allow"]
        if ip:
            if proto not in ("tcp", "udp", "both"):
                proto = "tcp"
            if proto == "both":
                for pr in ("tcp", "udp"):
                    _ufw_run(["allow", "from", ip, "to", "any", "port", str(port), "proto", pr])
                return jsonify({"ok": True, "msg": "已放行 %s → 端口 %s (tcp+udp)" % (ip, port)})
            args += ["from", ip, "to", "any", "port", str(port), "proto", proto]
        else:
            if proto == "both":
                args.append(str(port))
            else:
                args.append("%d/%s" % (port, proto))
        _ufw_run(args)
        return jsonify({"ok": True, "msg": "已放行 %s" % ("%s → %s/%s" % (ip, port, proto) if ip else "端口 %s" % port)})
    except Exception as e:
        return jsonify({"ok": False, "msg": "添加规则失败：%s" % e})

@panel.route("/firewall/delete", methods=["POST"])
@login_required
def firewall_delete():
    try:
        num = (request.form.get("num") or "").strip()
        if not num.isdigit():
            raise RuntimeError("缺少规则编号")
        num = int(num)
        rules = _ufw_rules_list()
        if rules is None:
            raise RuntimeError("未检测到 ufw")
        if not any(r.get("num") == num for r in rules):
            raise RuntimeError("未找到编号 %d 的规则" % num)
        current_ip = request.remote_addr or ""
        panel_port = _panel_port()
        if not _panel_access_after_delete(current_ip, panel_port, rules, num):
            raise RuntimeError(
                "已拒绝删除：移除规则 #%d 会导致当前 IP（%s）无法访问面板（端口 %d）。"
                "如确需删除，请先「放行当前 IP 到面板端口」。" % (num, current_ip, panel_port))
        _ufw_run(["--force", "delete", str(num)])
        return jsonify({"ok": True, "msg": "已删除规则 #%d" % num})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@panel.route("/status", methods=["POST"])
@login_required
def status():
    return jsonify(gather_status())

@panel.route("/restart_xray", methods=["POST"])
@login_required
def restart_xray():
    try:
        subprocess.Popen(["systemctl", "restart", XRAY_SERVICE_NAME],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"ok": True, "err": ""})
    except Exception as e:
        return jsonify({"ok": False, "err": str(e)})

@panel.route("/")
@login_required
def index():
    flash_msg = session.pop("flash_msg", None)
    flash_type = session.pop("flash_type", None)
    html, _ = _render_panel(flash_msg, flash_type)
    return html

def _render_panel(flash_msg, flash_type):
    xray_running = _xray_running()
    xray_ver = _xray_version()
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)

        inbounds = cfg.get("inbounds", [])
        real_nodes = real_node_inbounds(inbounds)
        _real_inbounds = [ib for _, ib in real_nodes]
        disabled_all = load_disabled()
        disabled_inb = load_disabled_inbounds()
        paused_ports = {d.get("port") for d in disabled_inb}

        traffic = traffic_store.read_totals()

        nodes = []
        nodes_json = []
        disabled_vless = [ib for ib in disabled_inb
                          if is_real_node(ib) and ib.get("protocol", "").lower() == "vless"]
        _vless_ports = sorted(
            [ib.get("port") for _, ib in real_nodes if ib.get("protocol") == "vless"]
            + [ib.get("port") for ib in disabled_vless])
        _vless_rank = {p: i + 1 for i, p in enumerate(_vless_ports)}
        _node_iter = list(real_nodes) + [(-1, ib) for ib in disabled_vless]
        for display_idx, (orig_idx, inbound) in enumerate(_node_iter):
            stream = inbound.get("streamSettings", {}) or {}
            reality = stream.get("realitySettings", {}) or {}
            port = inbound.get("port")
            network_raw = (stream.get("network") or "tcp").lower()
            if reality:
                sec = "reality"
            elif stream.get("tlsSettings"):
                sec = "tls"
            else:
                sec = "none"
            first_client = (inbound.get("settings", {}).get("clients") or [{}])[0] or {}
            nodes.append({
                "idx": display_idx + 1,
                "idx0": orig_idx,
                "protocol": inbound.get("protocol", "-").upper(),
                "port": port,
                "network": network_raw.upper(),
                "security": {"reality": "REALITY", "tls": "TLS", "none": "无"}.get(sec, sec),
                "sni": (reality.get("serverNames") or ["-"])[0],
                "dest": reality.get("dest", "-"),
                "remark": inbound.get("ui_remark", "") or "",
                "seq_name": (inbound.get("ui_remark") or "").strip() or ("vless%d" % _vless_rank.get(port, 0)),
                "status": "paused" if (port in paused_ports or orig_idx < 0) else "running",
                "protected": inbound_is_protected(port),
            })
            if orig_idx < 0:
                continue
            nodes_json.append({
                "port": port,
                "seq_name": (inbound.get("ui_remark") or "").strip() or ("vless%d" % _vless_rank.get(port, 0)),
                "remark": inbound.get("ui_remark", "") or "",
                "security": sec,
                "network": network_raw,
                "sni": (reality.get("serverNames") or [""])[0] or "",
                "dest": reality.get("dest", "") or "",
                "ws_path": (stream.get("wsSettings") or {}).get("path", "") or "",
                "grpc_service": (stream.get("grpcSettings") or {}).get("serviceName", "") or "",
                "client_id": first_client.get("id", "") or "",
                "private_key": reality.get("privateKey", "") or "",
                "public_key": stream.get("ui_public_key", "") or "",
                "protected": inbound_is_protected(port),
            })

        hy2_nodes_raw = load_hy2_nodes()
        hy2_nodes = []
        hy2_json = []
        for i, h in enumerate(hy2_nodes_raw):
            stats_listen = (h.get("stats") or {}).get("listen", "") or ""
            stats_port = stats_listen.rsplit(":", 1)[-1] if stats_listen else ""
            protected = h.get("id") in PROTECTED_HY2_IDS
            hy2_nodes.append({
                "id": h.get("id"),
                "name": h.get("name"),
                "seq_name": h.get("name") or ("hy%d" % (i + 1)),
                "port": h.get("port"),
                "security": (h.get("security") or "tls").upper(),
                "network": (h.get("network") or "UDP").upper(),
                "sni": h.get("sni") or "-",
                "enabled": h.get("enabled", True),
                "protected": protected,
            })
            hy2_json.append({
                "id": h.get("id"),
                "name": h.get("name"),
                "seq_name": h.get("name") or ("hy%d" % (i + 1)),
                "port": h.get("port"),
                "masquerade": h.get("masquerade", ""),
                "sni": h.get("sni", ""),
                "stats_port": stats_port,
                "protected": protected,
                "kind": "hy2",
                "key": h.get("id"),
            })

        fwd_nodes_raw = load_fwd_rules()
        fwd_nodes = []
        fwd_json = []
        for i, f in enumerate(fwd_nodes_raw):
            c = f.get("id") in PROTECTED_FWD_IDS
            _fwd_traffic = traffic.get("fwd:" + str(f.get("id")), {"up": 0, "down": 0})
            fwd_nodes.append({
                "id": f.get("id"),
                "name": f.get("name"),
                "seq_name": f.get("name") or ("fwd%d" % (i + 1)),
                "listen_port": f.get("listen_port"),
                "target_ip": f.get("target_ip"),
                "target_port": f.get("target_port"),
                "proto": ("TCP" if f.get("tcp") else "") +
                         ("+UDP" if f.get("udp") else ""),
                "enabled": f.get("enabled", True),
                "protected": c,
                "up": human_bytes(_fwd_traffic.get("up", 0)),
                "down": human_bytes(_fwd_traffic.get("down", 0)),
            })
            fwd_json.append({
                "id": f.get("id"),
                "name": f.get("name"),
                "listen_port": f.get("listen_port"),
                "target_ip": f.get("target_ip"),
                "target_port": f.get("target_port"),
                "tcp": f.get("tcp", True),
                "udp": f.get("udp", False),
                "protected": c,
            })

        data = get_users()
        users_recs = data["users"]
        hy2_by_id = {h.get("id"): h for h in hy2_nodes_raw}
        clients = []
        for u in users_recs:
            uname = u.get("name")
            t = traffic.get(uname, {"up": 0, "down": 0})
            hname_extra = u.get("hy2_name")
            if hname_extra and hname_extra != uname:
                t2 = traffic.get(hname_extra, {"up": 0, "down": 0})
                t = {"up": t["up"] + t2["up"], "down": t["down"] + t2["down"]}
            row = {
                "type": "user", "id": uname, "label": uname,
                "up": human_bytes(t["up"]), "down": human_bytes(t["down"]),
                "status": "paused" if u.get("disabled") else "running",
                "has_hy2": False,
                "has_vless": False,
                "is_admin": bool(uname in ADMIN_USERS),
                "nodes": [],
            }
            for b in u.get("bindings", []):
                if b.get("proto") == "vless":
                    port = b.get("node")
                    ib = next((x for x in _real_inbounds if int(x.get("port", 0)) == int(port)), None)
                    if ib is None:
                        continue
                    row["has_vless"] = True
                    row["nodes"].append({
                        "kind": "vless", "key": port, "port": port,
                        "label": "vless%d" % _vless_rank.get(int(port), 0),
                        "title": ("vless%d" % _vless_rank.get(int(port), 0)) + (" · :%d" % port),
                        "protected": inbound_is_protected(port),
                    })
                elif b.get("proto") == "hy2":
                    h = hy2_by_id.get(str(b.get("node")))
                    if h is None:
                        continue
                    row["has_hy2"] = True
                    hname = h.get("name") or h.get("id") or "-"
                    hport = h.get("port")
                    protected = h.get("id") in PROTECTED_HY2_IDS
                    seq = next((x.get("seq_name") for x in hy2_nodes
                                if x.get("id") == h.get("id")), None)
                    row["nodes"].append({
                        "kind": "hy2", "key": h.get("id"), "node_id": h.get("id"),
                        "port": hport,
                        "label": seq or hname,
                        "title": (seq or hname) + (" · :%s" % hport if hport else ""),
                        "protected": protected,
                    })
            clients.append(row)

        html = render_template_string(
            PANEL_HTML, ok=True, error=None,
            flash_msg=flash_msg, flash_type=flash_type,
            nodes=nodes,
            hy2_nodes=hy2_nodes,
            nodes_json=json.dumps(nodes_json, ensure_ascii=False),
            hy2_json=json.dumps(hy2_json, ensure_ascii=False),
            fwd_nodes=fwd_nodes,
            fwd_json=json.dumps(fwd_json, ensure_ascii=False),
            clients=clients,
            tenants=_limit_view(),
            limit_on=_limit_on(),
            allowlist_hint=(not os.path.exists(ALLOWLIST_HINT_FILE)),
            last_update=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            xray_running=xray_running, xray_ver=xray_ver,
        )
        return html, {"nodes": nodes_json, "hy2": hy2_json, "fwd": fwd_json}
    except Exception as e:
        html = render_template_string(PANEL_HTML, ok=False, error=f"{e}",
                                      flash_msg=flash_msg, flash_type=flash_type,
                                      nodes=[], hy2_nodes=[], fwd_nodes=[],
                                      nodes_json="[]", hy2_json="[]", fwd_json="[]", clients=[], tenants=[],
                                      xray_running=xray_running, xray_ver=xray_ver)
        return html, {"nodes": [], "hy2": [], "fwd": []}

@panel.route("/admin/add", methods=["POST"])
@login_required
def admin_add():
    name = (request.form.get("name") or "").strip()
    qg = (request.form.get("quota_gb") or "").strip()
    try:
        q = int(float(qg) * 1073741824)
    except Exception:
        q = 0
    if not name or q <= 0:
        return _panel_state("请填写名称与有效的总配额(GB)", ok=False)
    base_port = _limit_panel_port()
    made = {}
    def _mut(ts):
        if any(x.get("name") == name for x in ts):
            raise RuntimeError("limit用户名称已存在")
        pp = _alloc_panel_port(ts, base_port)
        if not pp:
            raise RuntimeError("无可用随机端口")
        tp = "p" + secrets.token_hex(5)
        user = "u" + secrets.token_hex(3)
        pw = _gen_pw(12)
        ts.append({"id": secrets.token_hex(6), "name": name, "path": tp, "user": user, "panel_port": pp,
                   "pass": pw,
                   "pass_hash": hashlib.sha256(pw.encode()).hexdigest(),
                   "quota_bytes": q, "used_up": 0, "used_down": 0, "last_up": 0, "last_down": 0,
                   "retired_up": 0, "retired_down": 0,
                   "exhausted": False, "enabled": True, "vless": [], "hy2": [], "fwd": [],
                   "created": datetime.datetime.now().isoformat(timespec="seconds")})
        made.update(port=pp, user=user, pw=pw, tp=tp)
    ok, err = _limit_update(_mut)
    if not ok:
        return _panel_state("创建失败：%s" % err, ok=False)
    return _panel_state("已创建limit用户 %s\n面板: http://%s:%s/%s/login\n账号: %s\n密码: %s（请立即保存）"
                        % (name, _server_addr(), made["port"], made["tp"], made["user"], made["pw"]), ok=True)

@panel.route("/admin/reset/<tid>", methods=["POST"])
@login_required
def admin_reset(tid):
    def _mut(ts):
        for t in ts:
            if t.get("id") == tid:
                t["used_up"] = 0; t["used_down"] = 0
                t["retired_up"] = 0; t["retired_down"] = 0
                t["exhausted"] = False; t["enabled"] = True
                for it in t.get("vless", []) + t.get("hy2", []) + t.get("fwd", []):
                    it["used_up"] = 0; it["used_down"] = 0
                return
        raise RuntimeError("未找到该limit用户")
    ok, err = _limit_update(_mut)
    if ok:
        return _panel_state("已重置该limit用户流量配额", ok=True)
    return _panel_state("重置失败：%s" % err, ok=False)

@panel.route("/admin/delete/<tid>", methods=["POST"])
@login_required
def admin_delete(tid):
    def _mut(ts):
        n = len(ts)
        ts[:] = [t for t in ts if t.get("id") != tid]
        if len(ts) == n:
            raise RuntimeError("未找到该limit用户")
    ok, err = _limit_update(_mut)
    if ok:
        return _panel_state("已删除limit用户（其节点/中转将在 limit 侧自动清理）", ok=True)
    return _panel_state("删除失败：%s" % err, ok=False)

@panel.route("/admin/limit_toggle", methods=["POST"])
@login_required
def admin_limit_toggle():
    on = (request.form.get("on") == "1")
    try:
        if on:
            try:
                os.remove(LIMIT_PAUSED_FILE)
            except Exception:
                pass
            subprocess.run(["systemctl", "start", "limit-xray"], timeout=25)
            for u in _limit_hy2_units():
                subprocess.run(["systemctl", "start", u], timeout=25)
            subprocess.run(["systemctl", "start", "limit-viewer"], timeout=25)
            _limit_state_cache.update(t=0.0, on=True)
            return jsonify({"ok": True, "msg": "limit 服务已开启"})
        else:
            try:
                os.makedirs(os.path.dirname(LIMIT_PAUSED_FILE), exist_ok=True)
                open(LIMIT_PAUSED_FILE, "w").write("1")
            except Exception:
                pass
            subprocess.run(["systemctl", "stop", "limit-viewer"], timeout=25)
            for u in _limit_hy2_units():
                subprocess.run(["systemctl", "stop", u], timeout=25)
            subprocess.run(["systemctl", "stop", "limit-xray"], timeout=25)
            _limit_state_cache.update(t=0.0, on=False)
            return jsonify({"ok": True, "msg": "limit 服务已暂停"})
    except Exception as e:
        return jsonify({"ok": False, "msg": "操作失败：%s" % e})

@panel.route("/panel_ack_allowlist", methods=["POST"])
@login_required
def panel_ack_allowlist():
    try:
        open(ALLOWLIST_HINT_FILE, "w").write("1")
    except Exception:
        pass
    return jsonify({"ok": True})


def _panel_state(msg, ok=True):
    html, js = _render_panel(None, None)
    return jsonify({"ok": ok, "msg": msg, "html": html,
                    "nodes": js["nodes"], "hy2": js["hy2"], "fwd": js["fwd"]})

app.register_blueprint(panel)

# Background traffic collector: only the worker that wins the flock keeps
# running, so traffic is counted exactly once even with several gunicorn workers.
def _start_collector():
    import fcntl
    lockf = open("/usr/local/etc/xray/.collector.lock", "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lockf.close()
        return
    from traffic_store import accumulate_once
    while True:
        try:
            accumulate_once()
        except Exception:
            pass
        time.sleep(5)

_collector = threading.Thread(target=_start_collector, daemon=True)
_collector.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=14325)

