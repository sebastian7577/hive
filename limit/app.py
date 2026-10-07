import json, os, sys, re, secrets, hashlib, subprocess, threading, time, datetime, fcntl, contextlib, socket, uuid, urllib.request, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, request, session, redirect, render_template_string, jsonify, Response
from flask.sessions import SecureCookieSessionInterface
import traffic_store

BASE = "/opt/limit"
DATA_DIR = BASE + "/data"
TENANTS_PATH = DATA_DIR + "/tenants.json"
LOCK_PATH = DATA_DIR + "/.tenants.lock"
XRAY_CONFIG = BASE + "/xray/config.json"
XRAY_SIG = BASE + "/xray/.applied.sig"
HY2_DIR = BASE + "/hysteria/conf.d"
HY2_CRT = BASE + "/hysteria/server.crt"
HY2_KEY = BASE + "/hysteria/server.key"
SECRET_FILE = BASE + "/secret_key"
LOGIN_LOCK_PATH = DATA_DIR + "/login_lock.json"
PANEL_PORT_FILE = BASE + "/panel_port"
SERVER_IP_FILE = BASE + "/server_ip"
XRAY_API = "127.0.0.1:10185"
XRAY_SVC = "limit-xray"
HY2_UNIT = "limit-hysteria@%s"
UFW_TRACK = DATA_DIR + "/ufw_ports.json"
HY2_USER = "u"
HY2_SNI = "www.amazon.com"
SITES = ["www.amazon.com", "www.microsoft.com", "www.bing.com", "www.apple.com",
         "www.cloudflare.com", "www.wikipedia.org", "www.samsung.com", "www.icloud.com"]

VLESS_RANGE = (21000, 21999)
FWD_RANGE = (22000, 29999)
HY2_RANGE = (30000, 30999)
SESSION_TTL = 3600
LOCK_FAIL = 3
LOCK_SECONDS = 6 * 3600


def find_xray():
    for p in ("/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"):
        if os.path.exists(p):
            return p
    return "xray"


XRAY_BIN = find_xray()

try:
    BASE_CSS = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "base.css"), encoding="utf-8").read()
except Exception:
    BASE_CSS = ""

app = Flask(__name__)


class _TenantSession(SecureCookieSessionInterface):
    """每个租户用独立 cookie 名（按请求端口），避免同主机下不同租户/主面板
    共用 "session" cookie 互相覆盖导致掉登录。"""
    def get_cookie_name(self, app):
        try:
            p = (request.host or "").rsplit(":", 1)[-1]
            if p and p.isdigit():
                return "limit_sess_" + p
        except Exception:
            pass
        return app.config.get("SESSION_COOKIE_NAME", "limit_sess")


app.session_interface = _TenantSession()


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception as e:
        class R:
            returncode = 1; stdout = ""; stderr = str(e)
        return R()


HELPER_SOCK = "/run/limit-helper.sock"


def _priv(**req):
    """Call the privileged root helper (systemctl / ufw / iptables). Returns dict."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(35)
        s.connect(HELPER_SOCK)
        s.sendall((json.dumps(req) + "\n").encode())
        data = b""
        while b"\n" not in data and len(data) < 65536:
            c = s.recv(4096)
            if not c:
                break
            data += c
        s.close()
        return json.loads(data.decode().strip() or "{}")
    except Exception as e:
        return {"ok": False, "err": str(e)}


def gen_reality_keys():
    r = _run([XRAY_BIN, "x25519"])
    out = (r.stdout or "") + (r.stderr or "")
    m1 = re.search(r"PrivateKey:\s*(\S+)", out)
    m2 = re.search(r"\(PublicKey\)[:\s]+(\S+)", out) or re.search(r"PublicKey:\s*(\S+)", out)
    if not m1 or not m2:
        raise RuntimeError("生成 REALITY 密钥失败：%s" % out.strip()[:200])
    return m1.group(1), m2.group(1)


def _load_secret():
    try:
        s = open(SECRET_FILE).read().strip()
        if len(s) >= 32:
            return s
    except Exception:
        pass
    s = secrets.token_hex(32)
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, s.encode()); os.close(fd)
    except Exception:
        pass
    return s


def _server_ip():
    try:
        v = open(SERVER_IP_FILE).read().strip()
        if v:
            return v
    except Exception:
        pass
    ip = ""
    try:
        ip = urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
    except Exception:
        ip = ""
    if ip:
        try:
            open(SERVER_IP_FILE, "w").write(ip)
        except Exception:
            pass
    return ip or "SERVER_IP"


SERVER_IP = _server_ip()
app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="limit_sess",
                  PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=1))


def _base_port():
    try:
        return open(PANEL_PORT_FILE).read().strip()
    except Exception:
        return ""


@contextlib.contextmanager
def _lock():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(LOCK_PATH, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _migrate(ts):
    for t in ts:
        t.setdefault("retired_up", 0)
        t.setdefault("retired_down", 0)
        for n in t.get("vless", []):
            n.setdefault("security", "none")
            n.setdefault("network", "tcp")
            n.setdefault("sni", "")
            if "clients" in n:
                cl = n.pop("clients") or []
                if not n.get("uuid") and cl:
                    n["uuid"] = cl[0].get("uuid")
                n["used_up"] = n.get("used_up", 0) + sum(c.get("used_up", 0) for c in cl)
                n["used_down"] = n.get("used_down", 0) + sum(c.get("used_down", 0) for c in cl)
                n.pop("last_up", None); n.pop("last_down", None)
            if not n.get("uuid"):
                n["uuid"] = str(uuid.uuid4())
            for k in ("last_up", "last_down", "used_up", "used_down"):
                n.setdefault(k, 0)
        for h in t.get("hy2", []):
            h.setdefault("name", "hy2%d" % h.get("port", 0))
            h.setdefault("sni", HY2_SNI)
            h.setdefault("masquerade", "https://" + h.get("sni", HY2_SNI))
            if "clients" in h:
                cl = h.pop("clients") or []
                if not h.get("password") and cl:
                    h["password"] = cl[0].get("password")
                h["used_up"] = h.get("used_up", 0) + sum(c.get("used_up", 0) for c in cl)
                h["used_down"] = h.get("used_down", 0) + sum(c.get("used_down", 0) for c in cl)
                h.pop("last_up", None); h.pop("last_down", None)
            if not h.get("password"):
                h["password"] = uuid.uuid4().hex
            for k in ("last_up", "last_down", "used_up", "used_down"):
                h.setdefault(k, 0)
        for f in t.get("fwd", []):
            f.setdefault("name", "fwd%d" % f.get("listen_port", 0))
    return ts


def load_tenants():
    try:
        d = json.load(open(TENANTS_PATH))
        ts = d.get("tenants", []) if isinstance(d, dict) else d
        if not isinstance(ts, list):
            return []
    except Exception:
        return []
    return _migrate(ts)


def save_tenants(ts):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = TENANTS_PATH + ".tmp"
    json.dump({"tenants": ts}, open(tmp, "w"), indent=2, ensure_ascii=False)
    os.replace(tmp, TENANTS_PATH)


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def human(n):
    try:
        n = float(n)
    except Exception:
        return "0B"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f%s" % (n, u)
        n /= 1024
    return "%.1fPB" % n


def _lk_load():
    try:
        return json.load(open(LOGIN_LOCK_PATH))
    except Exception:
        return {}


def _lk_save(d):
    try:
        tmp = LOGIN_LOCK_PATH + ".tmp"
        json.dump(d, open(tmp, "w")); os.replace(tmp, LOGIN_LOCK_PATH)
    except Exception:
        pass


def _lk_left(tid, ip):
    d = _lk_load().get("%s|%s" % (tid, ip))
    return max(0, int(d.get("until", 0) - time.time())) if d else 0


def _lk_fail(tid, ip):
    d = _lk_load(); k = "%s|%s" % (tid, ip)
    rec = d.get(k) or {"fails": 0, "until": 0}
    rec["fails"] = rec.get("fails", 0) + 1
    if rec["fails"] >= LOCK_FAIL:
        rec["until"] = time.time() + LOCK_SECONDS; rec["fails"] = 0
    d[k] = rec; _lk_save(d)


def _lk_clear(tid, ip):
    d = _lk_load(); d.pop("%s|%s" % (tid, ip), None); _lk_save(d)


def _used_ports(ts):
    u = set()
    for t in ts:
        for n in t.get("vless", []):
            u.add(int(n["port"]))
        for f in t.get("fwd", []):
            u.add(int(f["listen_port"]))
        for h in t.get("hy2", []):
            u.add(int(h["port"]))
    return u


def _port_free(p, udp=True):
    for typ in ([socket.SOCK_STREAM, socket.SOCK_DGRAM] if udp else [socket.SOCK_STREAM]):
        s = socket.socket(socket.AF_INET, typ)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", p))
        except Exception:
            return False
        finally:
            s.close()
    return True


def check_port(ts, port, udp, rng):
    try:
        port = int(port)
    except Exception:
        raise RuntimeError("端口无效")
    if not 1 <= port <= 65535:
        raise RuntimeError("端口必须在 1-65535")
    if port == int(_base_port() or 0):
        raise RuntimeError("端口 %d 为面板端口" % port)
    if port in _used_ports(ts):
        raise RuntimeError("端口 %d 已被占用" % port)
    if not _port_free(port, udp):
        raise RuntimeError("端口 %d 已被系统占用" % port)
    return port


def ufw_allow(port, udp):
    _priv(op="ufw", action="allow", port=int(port), proto="tcp")
    if udp:
        _priv(op="ufw", action="allow", port=int(port), proto="udp")


def ufw_delete(port, udp):
    _priv(op="ufw", action="delete", port=int(port), proto="tcp")
    if udp:
        _priv(op="ufw", action="delete", port=int(port), proto="udp")


def _ufw_tracked():
    try:
        return set(tuple(x) for x in json.load(open(UFW_TRACK)))
    except Exception:
        return set()


def _ufw_set(s):
    try:
        json.dump(sorted(list(s)), open(UFW_TRACK, "w"))
    except Exception:
        pass


def _redir_sync(ports):
    base = _base_port()
    if not base:
        return
    try:
        ports = [int(x) for x in ports if x]
    except Exception:
        return
    _priv(op="iptables_redir", base=int(base), ports=ports)


def _on(x):
    return x.get("enabled", True)


def _vless_email(tid, port):
    return "t%s-v%s" % (tid, port)


def _vless_tag(tid, port):
    return "t%s-vless-%s" % (tid, port)


def _fwd_tag(tid, fid, proto):
    return "t%s-fwd-%s-%s" % (tid, fid, proto)


def _hy2_nid(tid, nid):
    return "t%s-hy2-%s" % (tid, nid)


def _vless_flow(node):
    if node.get("security") == "reality" and node.get("network", "tcp") == "tcp":
        return "xtls-rprx-vision"
    return ""


def _stream(node):
    sec = node.get("security", "none"); net = node.get("network", "tcp")
    sni = node.get("sni", "") or HY2_SNI
    st = {"network": net, "security": "none"}
    if sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {"show": True, "dest": node.get("dest") or (sni + ":443"), "xver": 0,
                                 "serverNames": [sni], "privateKey": node.get("reality_private", ""),
                                 "shortIds": [node.get("short_id", "")]}
    elif sec == "tls":
        st["security"] = "tls"
        st["tlsSettings"] = {"serverName": sni, "alpn": ["h2", "http/1.1"],
                             "certificates": [{"certificateFile": HY2_CRT, "keyFile": HY2_KEY}]}
    if net == "ws":
        st["wsSettings"] = {"path": node.get("ws_path") or "/", "headers": {"Host": sni}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": node.get("grpc_service") or "vless"}
    return st


def build_xray_config(ts):
    inbounds = []
    for t in ts:
        if t.get("exhausted") or not t.get("enabled", True):
            continue
        for n in t.get("vless", []):
            if not _on(n):
                continue
            cl = {"id": n["uuid"], "email": _vless_email(t["id"], n["port"])}
            flow = _vless_flow(n)
            if flow:
                cl["flow"] = flow
            inbounds.append({"listen": "0.0.0.0", "port": int(n["port"]), "protocol": "vless",
                             "settings": {"clients": [cl], "decryption": "none"},
                             "streamSettings": _stream(n),
                             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                             "tag": _vless_tag(t["id"], n["port"])})
        for f in t.get("fwd", []):
            if not _on(f):
                continue
            for proto in ("tcp", "udp"):
                if (proto == "tcp" and f.get("tcp")) or (proto == "udp" and f.get("udp")):
                    inbounds.append({"listen": "0.0.0.0", "port": int(f["listen_port"]), "protocol": "dokodemo-door",
                                     "settings": {"address": f["target_ip"], "port": int(f["target_port"]), "network": proto},
                                     "tag": _fwd_tag(t["id"], f["id"], proto)})
    inbounds.append({"listen": "127.0.0.1", "port": int(XRAY_API.split(":")[1]),
                     "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api"})
    return {
        "log": {"loglevel": "warning", "access": "/dev/null"},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"},
                      {"protocol": "blackhole", "tag": "block"},
                      {"protocol": "freedom", "tag": "api"}],
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                              "statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "api": {"tag": "api", "services": ["StatsService"]},
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]},
    }


def _sig(ts):
    rel = []
    for t in ts:
        rel.append({"id": t["id"], "e": t.get("enabled", True), "x": t.get("exhausted", False),
                    "pp": t.get("panel_port"),
                    "v": [[n["port"], _on(n), n.get("security"), n.get("network"), n.get("sni"),
                           n.get("reality_private"), n.get("short_id"), n.get("uuid")]
                          for n in t.get("vless", [])],
                    "f": [[f["listen_port"], f["target_ip"], f["target_port"], f.get("tcp"), f.get("udp"), _on(f)]
                          for f in t.get("fwd", [])],
                    "h": [[h["id"], h["port"], h.get("listen"), h.get("secret"), h.get("sni"),
                           h.get("masquerade"), h.get("password"), _on(h)] for h in t.get("hy2", [])]})
    return hashlib.sha256(json.dumps(rel, sort_keys=True).encode()).hexdigest()


def _hy2_yaml(port, password, listen, secret, masq):
    lines = ["listen: :%d" % int(port), "",
             "tls:", "  cert: %s" % HY2_CRT, "  key: %s" % HY2_KEY, "",
             "auth:", "  type: password", "  password: '%s'" % str(password).replace("'", "''")]
    if masq:
        lines += ["", "masquerade:", "  type: proxy", "  proxy:",
                  "    url: %s" % masq, "    rewriteHost: true"]
    lines += ["", "trafficStats:", "  listen: %s" % listen, "  secret: %s" % secret]
    return "\n".join(lines) + "\n"


def apply_all(ts, do_redir=True):
    cfg = json.dumps(build_xray_config(ts), indent=2)
    os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
    try:
        cur = open(XRAY_CONFIG).read()
    except Exception:
        cur = None
    if cur != cfg:
        tmp = XRAY_CONFIG + ".tmp"
        open(tmp, "w").write(cfg)
        try:
            os.chmod(tmp, 0o644)
        except Exception:
            pass
        os.replace(tmp, XRAY_CONFIG)
        _priv(op="systemctl", action="restart", unit=XRAY_SVC)

    os.makedirs(HY2_DIR, exist_ok=True)
    want = {}
    for t in ts:
        if t.get("exhausted") or not t.get("enabled", True):
            continue
        for h in t.get("hy2", []):
            if not _on(h):
                continue
            want[_hy2_nid(t["id"], h["id"])] = (h["port"], h.get("password"), h.get("listen", "127.0.0.1:0"),
                                                h.get("secret", ""), h.get("masquerade", ""))
    for fn in os.listdir(HY2_DIR):
        if fn.endswith(".yaml") and fn[:-5] not in want:
            _priv(op="systemctl", action="disable", unit=HY2_UNIT % fn[:-5])
            try:
                os.remove(os.path.join(HY2_DIR, fn))
            except Exception:
                pass
    for nid, (port, password, listen, secret, masq) in want.items():
        path = os.path.join(HY2_DIR, nid + ".yaml")
        content = _hy2_yaml(port, password, listen, secret, masq)
        try:
            prev = open(path).read()
        except Exception:
            prev = None
        changed = (prev != content)
        if changed:
            open(path, "w").write(content)
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
        unit = HY2_UNIT % nid
        _priv(op="systemctl", action="enable", unit=unit)
        active = _run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
        if not active:
            _priv(op="systemctl", action="start", unit=unit)
        elif changed:
            _priv(op="systemctl", action="restart", unit=unit)

    desired = set()
    for t in ts:
        for n in t.get("vless", []):
            desired.add((int(n["port"]), "tcp"))
        for f in t.get("fwd", []):
            if f.get("tcp"):
                desired.add((int(f["listen_port"]), "tcp"))
            if f.get("udp"):
                desired.add((int(f["listen_port"]), "udp"))
        for h in t.get("hy2", []):
            desired.add((int(h["port"]), "udp"))
    for (p, proto) in (_ufw_tracked() - desired):
        _priv(op="ufw", action="delete", port=int(p), proto=proto)
    _ufw_set(desired)

    if do_redir:
        _redir_sync([t.get("panel_port") for t in ts])
    try:
        open(XRAY_SIG, "w").write(_sig(ts))
    except Exception:
        pass


def _collect_once():
    ts0 = load_tenants()
    xuser = traffic_store.get_xray_user_map(XRAY_API)
    xin = traffic_store.get_xray_inbound_map(XRAY_API)
    hy2nodes = [{"id": _hy2_nid(t["id"], h["id"]), "listen": h.get("listen", "127.0.0.1:0"),
                 "secret": h.get("secret", "")} for t in ts0 for h in t.get("hy2", [])]
    hy2u = traffic_store.get_hy2_users(hy2nodes)

    lk = open(LOCK_PATH, "w"); fcntl.flock(lk, fcntl.LOCK_EX)
    ts = load_tenants()
    dirty = changed = False
    used_pp = {int(t.get("panel_port", 0)) for t in ts if t.get("panel_port")}
    _bp = int(_base_port() or 0)
    for t in ts:
        if not t.get("panel_port"):
            for _ in range(300):
                cand = secrets.randbelow(10000) + 40000
                if cand == _bp or cand in used_pp:
                    continue
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("0.0.0.0", cand)); s.close()
                except Exception:
                    continue
                t["panel_port"] = cand; used_pp.add(cand); changed = True
                break
    for t in ts:
        tup = int(t.get("retired_up", 0)); tdown = int(t.get("retired_down", 0))
        for n in t.get("vless", []):
            e = xuser.get(_vless_email(t["id"], n["port"]))
            up = e["up"] if e else 0; down = e["down"] if e else 0
            lu = n.get("last_up", 0); ld = n.get("last_down", 0)
            du = up - lu if up >= lu else up
            dd = down - ld if down >= ld else down
            if du or dd:
                n["used_up"] = n.get("used_up", 0) + du
                n["used_down"] = n.get("used_down", 0) + dd
                dirty = True
            n["last_up"] = up; n["last_down"] = down
            tup += n.get("used_up", 0); tdown += n.get("used_down", 0)
        for f in t.get("fwd", []):
            fup = fdown = 0
            for proto in ("tcp", "udp"):
                if (proto == "tcp" and not f.get("tcp")) or (proto == "udp" and not f.get("udp")):
                    continue
                e = xin.get(_fwd_tag(t["id"], f["id"], proto))
                if e:
                    fup += e["up"]; fdown += e["down"]
            lu = f.get("last_up", 0); ld = f.get("last_down", 0)
            du = fup - lu if fup >= lu else fup
            dd = fdown - ld if fdown >= ld else fdown
            if du or dd:
                f["used_up"] = f.get("used_up", 0) + du
                f["used_down"] = f.get("used_down", 0) + dd
                dirty = True
            f["last_up"] = fup; f["last_down"] = fdown
            tup += f.get("used_up", 0); tdown += f.get("used_down", 0)
        for h in t.get("hy2", []):
            umap = hy2u.get(_hy2_nid(t["id"], h["id"]), {})
            up = sum(x.get("up", 0) for x in umap.values())
            down = sum(x.get("down", 0) for x in umap.values())
            lu = h.get("last_up", 0); ld = h.get("last_down", 0)
            du = up - lu if up >= lu else up
            dd = down - ld if down >= ld else down
            if du or dd:
                h["used_up"] = h.get("used_up", 0) + du
                h["used_down"] = h.get("used_down", 0) + dd
                dirty = True
            h["last_up"] = up; h["last_down"] = down
            tup += h.get("used_up", 0); tdown += h.get("used_down", 0)
        if t.get("used_up", 0) != tup or t.get("used_down", 0) != tdown:
            t["used_up"] = tup; t["used_down"] = tdown
            dirty = True
        total = tup + tdown
        if t.get("quota_bytes", 0) and total >= t["quota_bytes"] and not t.get("exhausted"):
            t["exhausted"] = True; t["enabled"] = False; changed = True
    if dirty or changed:
        save_tenants(ts)
    try:
        fcntl.flock(lk, fcntl.LOCK_UN); lk.close()
    except Exception:
        pass
    try:
        applied = open(XRAY_SIG).read().strip()
    except Exception:
        applied = ""
    if _sig(ts) != applied:
        apply_all(ts)


def _collector():
    while True:
        try:
            _collect_once()
        except Exception:
            pass
        time.sleep(5)


threading.Thread(target=_collector, daemon=True).start()


def _req_port():
    h = request.host or ""
    return h.rsplit(":", 1)[1] if ":" in h else ""


def _tenant_by_req(pt=None):
    p = _req_port()
    if not p:
        return None
    for t in load_tenants():
        if str(t.get("panel_port")) == p:
            if pt is not None and pt != t.get("path"):
                return None
            return t
    return None


def _authed(tid):
    return session.get("auth:" + tid) and (time.time() - session.get("t:" + tid, 0) < SESSION_TTL)


def _need(pt):
    t = _tenant_by_req(pt)
    return t if (t and _authed(t["id"])) else None


def _set_flash(msg, ok=True):
    session["f"] = msg
    session["fok"] = bool(ok)


def _take_flash():
    return session.pop("f", None), session.pop("fok", True)


def _find_node(t, kind, key):
    if kind == "vless":
        return next((n for n in t.get("vless", []) if str(n["port"]) == str(key)), None)
    if kind == "hy2":
        return next((h for h in t.get("hy2", []) if h["id"] == key), None)
    if kind == "fwd":
        return next((f for f in t.get("fwd", []) if f["id"] == key), None)
    return None


def _q(s):
    return urllib.parse.quote(str(s), safe="")


def vless_link(node):
    sec = node.get("security", "none"); net = node.get("network", "tcp")
    q = [("encryption", "none")]
    flow = _vless_flow(node)
    if flow:
        q.append(("flow", flow))
    if net == "grpc":
        q.append(("type", "grpc")); q.append(("serviceName", node.get("grpc_service") or "vless"))
    elif net == "ws":
        q.append(("type", "ws"))
        if node.get("ws_path"):
            q.append(("path", node["ws_path"]))
        if node.get("sni"):
            q.append(("host", node["sni"]))
    else:
        q.append(("type", "tcp"))
    if sec == "reality":
        q.append(("security", "reality"))
        if node.get("sni"):
            q.append(("sni", node["sni"]))
        q.append(("fp", "chrome"))
        if node.get("reality_public"):
            q.append(("pbk", node["reality_public"]))
        if node.get("short_id"):
            q.append(("sid", node["short_id"]))
    elif sec == "tls":
        q.append(("security", "tls")); q.append(("fp", "chrome"))
        if node.get("sni"):
            q.append(("sni", node["sni"]))
    else:
        q.append(("security", "none"))
    qs = "&".join("%s=%s" % (k, _q(v)) for k, v in q)
    return "vless://%s@%s:%d?%s#%s" % (node["uuid"], SERVER_IP, int(node["port"]), qs,
                                       _q(node.get("remark") or "vless"))


def hy2_link(node):
    q = []
    if node.get("sni"):
        q.append("sni=%s" % _q(node["sni"]))
    q.append("insecure=1")
    return "hysteria2://%s@%s:%d/?%s#%s" % (
        _q(node.get("password", "")), SERVER_IP, int(node["port"]), "&".join(q),
        _q(node.get("name") or "hy2"))


QRLIB = r'''/**
 * Minified by jsDelivr using Terser v5.37.0.
 * Original file: /npm/qrcode-generator@1.4.4/qrcode.js
 *
 * Do NOT use SRI with dynamically generated files! More information: https://www.jsdelivr.com/using-sri-with-dynamic-files
 */
var qrcode=function(){var t=function(t,r){var e=t,n=g[r],o=null,i=0,a=null,u=[],f={},c=function(t,r){o=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(i=4*e+17),l(0,0),l(i-7,0),l(0,i-7),s(),h(),d(t,r),e>=7&&v(t),null==a&&(a=p(e,n,u)),w(a,r)},l=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||i<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||i<=r+n||(o[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},h=function(){for(var t=8;t<i-8;t+=1)null==o[t][6]&&(o[t][6]=t%2==0);for(var r=8;r<i-8;r+=1)null==o[6][r]&&(o[6][r]=r%2==0)},s=function(){for(var t=B.getPatternPosition(e),r=0;r<t.length;r+=1)for(var n=0;n<t.length;n+=1){var i=t[r],a=t[n];if(null==o[i][a])for(var u=-2;u<=2;u+=1)for(var f=-2;f<=2;f+=1)o[i+u][a+f]=-2==u||2==u||-2==f||2==f||0==u&&0==f}},v=function(t){for(var r=B.getBCHTypeNumber(e),n=0;n<18;n+=1){var a=!t&&1==(r>>n&1);o[Math.floor(n/3)][n%3+i-8-3]=a}for(n=0;n<18;n+=1){a=!t&&1==(r>>n&1);o[n%3+i-8-3][Math.floor(n/3)]=a}},d=function(t,r){for(var e=n<<3|r,a=B.getBCHTypeInfo(e),u=0;u<15;u+=1){var f=!t&&1==(a>>u&1);u<6?o[u][8]=f:u<8?o[u+1][8]=f:o[i-15+u][8]=f}for(u=0;u<15;u+=1){f=!t&&1==(a>>u&1);u<8?o[8][i-u-1]=f:u<9?o[8][15-u-1+1]=f:o[8][15-u-1]=f}o[i-8][8]=!t},w=function(t,r){for(var e=-1,n=i-1,a=7,u=0,f=B.getMaskFunction(r),c=i-1;c>0;c-=2)for(6==c&&(c-=1);;){for(var g=0;g<2;g+=1)if(null==o[n][c-g]){var l=!1;u<t.length&&(l=1==(t[u]>>>a&1)),f(n,c-g)&&(l=!l),o[n][c-g]=l,-1==(a-=1)&&(u+=1,a=7)}if((n+=e)<0||i<=n){n-=e,e=-e;break}}},p=function(t,r,e){for(var n=A.getRSBlocks(t,r),o=b(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=k(i[u],l.getLength()-1).mod(l);for(a[u]=new Array(l.getLength()-1),g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=s>=0?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};f.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=M(t);break;case"Alphanumeric":e=x(t);break;case"Byte":e=m(t);break;case"Kanji":e=L(t);break;default:throw"mode:"+r}u.push(e),a=null},f.isDark=function(t,r){if(t<0||i<=t||r<0||i<=r)throw t+","+r;return o[t][r]},f.getModuleCount=function(){return i},f.make=function(){if(e<1){for(var t=1;t<40;t++){for(var r=A.getRSBlocks(t,n),o=b(),i=0;i<u.length;i++){var a=u[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var g=0;for(i=0;i<r.length;i++)g+=r[i].dataCount;if(o.getLengthInBits()<=8*g)break}e=t}c(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){c(!0,e);var n=B.getLostPoint(f);(0==e||t>n)&&(t=n,r=e)}return r}())},f.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<f.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<f.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=f.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},f.createSvgTag=function(t,r,e,n){var o={};"object"==typeof arguments[0]&&(t=(o=arguments[0]).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,c,g=f.getModuleCount()*t+2*r,l="";for(c="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",l+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',l+=o.scalable?"":' width="'+g+'px" height="'+g+'px"',l+=' viewBox="0 0 '+g+" "+g+'" ',l+=' preserveAspectRatio="xMinYMin meet"',l+=n.text||e.text?' role="img" aria-labelledby="'+y([n.id,e.id].join(" ").trim())+'"':"",l+=">",l+=n.text?'<title id="'+y(n.id)+'">'+y(n.text)+"</title>":"",l+=e.text?'<description id="'+y(e.id)+'">'+y(e.text)+"</description>":"",l+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',l+='<path d="',a=0;a<f.getModuleCount();a+=1)for(u=a*t+r,i=0;i<f.getModuleCount();i+=1)f.isDark(a,i)&&(l+="M"+(i*t+r)+","+u+c);return l+='" stroke="transparent" fill="black"/>',l+="</svg>"},f.createDataURL=function(t,r){t=t||2,r=void 0===r?4*t:r;var e=f.getModuleCount()*t+2*r,n=r,o=e-r;return I(e,e,(function(r,e){if(n<=r&&r<o&&n<=e&&e<o){var i=Math.floor((r-n)/t),a=Math.floor((e-n)/t);return f.isDark(a,i)?0:1}return 1}))},f.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=f.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=f.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=y(e),o+='"'),o+="/>"};var y=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return f.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*f.getModuleCount()+2*t,u=t,c=a-t,g={"██":"█","█ ":"▀"," █":"▄","  ":" "},l={"██":"▀","█ ":"▀"," █":" ","  ":" "},h="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<c&&u<=r&&r<c&&f.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<c&&u<=r+1&&r+1<c&&f.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",h+=t<1&&r+1>=c?l[i]:g[i];h+="\n"}return a%2&&t>0?h.substring(0,h.length-a-1)+Array(a+1).join("▀"):h.substring(0,h.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=f.getModuleCount()*t+2*r,u=r,c=a-r,g=Array(t+1).join("██"),l=Array(t+1).join("  "),h="",s="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),s="",n=0;n<a;n+=1)i=1,u<=n&&n<c&&u<=e&&e<c&&f.isDark(o,Math.floor((n-u)/t))&&(i=0),s+=i?g:l;for(o=0;o<t;o+=1)h+=s+"\n"}return h.substring(0,h.length-1)},f.renderTo2dContext=function(t,r){r=r||2;for(var e=f.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=f.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},f};t.stringToBytes=(t.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,t.createStringToBytes=function(t,r){var e=function(){for(var e=S(t),n=function(){var t=e.read();if(-1==t)throw"eof";return t},o=0,i={};;){var a=e.read();if(-1==a)break;var u=n(),f=n()<<8|n();i[String.fromCharCode(a<<8|u)]=f,o+=1}if(o!=r)throw o+" != "+r;return i}(),n="?".charCodeAt(0);return function(t){for(var r=[],o=0;o<t.length;o+=1){var i=t.charCodeAt(o);if(i<128)r.push(i);else{var a=e[t.charAt(o)];"number"==typeof a?(255&a)==a?r.push(a):(r.push(a>>>8),r.push(255&a)):r.push(n)}}return r}};var r,e,n,o,i,a=1,u=2,f=4,c=8,g={L:1,M:0,Q:3,H:2},l=0,h=1,s=2,v=3,d=4,w=5,p=6,y=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],e=1335,n=7973,i=function(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r},(o={}).getBCHTypeInfo=function(t){for(var r=t<<10;i(r)-i(e)>=0;)r^=e<<i(r)-i(e);return 21522^(t<<10|r)},o.getBCHTypeNumber=function(t){for(var r=t<<12;i(r)-i(n)>=0;)r^=n<<i(r)-i(n);return t<<12|r},o.getPatternPosition=function(t){return r[t-1]},o.getMaskFunction=function(t){switch(t){case l:return function(t,r){return(t+r)%2==0};case h:return function(t,r){return t%2==0};case s:return function(t,r){return r%3==0};case v:return function(t,r){return(t+r)%3==0};case d:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case w:return function(t,r){return t*r%2+t*r%3==0};case p:return function(t,r){return(t*r%2+t*r%3)%2==0};case y:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},o.getErrorCorrectPolynomial=function(t){for(var r=k([1],0),e=0;e<t;e+=1)r=r.multiply(k([1,C.gexp(e)],0));return r},o.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case f:case c:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case f:return 16;case c:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case f:return 16;case c:return 12;default:throw"mode:"+t}}},o.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);i>5&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},o),C=function(){for(var t=new Array(256),r=new Array(256),e=0;e<8;e+=1)t[e]=1<<e;for(e=8;e<256;e+=1)t[e]=t[e-4]^t[e-5]^t[e-6]^t[e-8];for(e=0;e<255;e+=1)r[t[e]]=e;var n={glog:function(t){if(t<1)throw"glog("+t+")";return r[t]},gexp:function(r){for(;r<0;)r+=255;for(;r>=256;)r-=255;return t[r]}};return n}();function k(t,r){if(void 0===t.length)throw t.length+"/"+r;var e=function(){for(var e=0;e<t.length&&0==t[e];)e+=1;for(var n=new Array(t.length-e+r),o=0;o<t.length-e;o+=1)n[o]=t[o+e];return n}(),n={getAt:function(t){return e[t]},getLength:function(){return e.length},multiply:function(t){for(var r=new Array(n.getLength()+t.getLength()-1),e=0;e<n.getLength();e+=1)for(var o=0;o<t.getLength();o+=1)r[e+o]^=C.gexp(C.glog(n.getAt(e))+C.glog(t.getAt(o)));return k(r,0)},mod:function(t){if(n.getLength()-t.getLength()<0)return n;for(var r=C.glog(n.getAt(0))-C.glog(t.getAt(0)),e=new Array(n.getLength()),o=0;o<n.getLength();o+=1)e[o]=n.getAt(o);for(o=0;o<t.getLength();o+=1)e[o]^=C.gexp(C.glog(t.getAt(o))+r);return k(e,0).mod(t)}};return n}var A=function(){var t=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],r=function(t,r){var e={};return e.totalCount=t,e.dataCount=r,e},e={};return e.getRSBlocks=function(e,n){var o=function(r,e){switch(e){case g.L:return t[4*(r-1)+0];case g.M:return t[4*(r-1)+1];case g.Q:return t[4*(r-1)+2];case g.H:return t[4*(r-1)+3];default:return}}(e,n);if(void 0===o)throw"bad rs block @ typeNumber:"+e+"/errorCorrectionLevel:"+n;for(var i=o.length/3,a=[],u=0;u<i;u+=1)for(var f=o[3*u+0],c=o[3*u+1],l=o[3*u+2],h=0;h<f;h+=1)a.push(r(c,l));return a},e}(),b=function(){var t=[],r=0,e={getBuffer:function(){return t},getAt:function(r){var e=Math.floor(r/8);return 1==(t[e]>>>7-r%8&1)},put:function(t,r){for(var n=0;n<r;n+=1)e.putBit(1==(t>>>r-n-1&1))},getLengthInBits:function(){return r},putBit:function(e){var n=Math.floor(r/8);t.length<=n&&t.push(0),e&&(t[n]|=128>>>r%8),r+=1}};return e},M=function(t){var r=a,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+2<r.length;)t.put(o(r.substring(n,n+3)),10),n+=3;n<r.length&&(r.length-n==1?t.put(o(r.substring(n,n+1)),4):r.length-n==2&&t.put(o(r.substring(n,n+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return n},x=function(t){var r=u,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+1<r.length;)t.put(45*o(r.charAt(n))+o(r.charAt(n+1)),11),n+=2;n<r.length&&t.put(o(r.charAt(n)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return n},m=function(r){var e=f,n=t.stringToBytes(r),o={getMode:function(){return e},getLength:function(t){return n.length},write:function(t){for(var r=0;r<n.length;r+=1)t.put(n[r],8)}};return o},L=function(r){var e=c,n=t.stringToBytesFuncs.SJIS;if(!n)throw"sjis not supported.";!function(){var t=n("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=n(r),i={getMode:function(){return e},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return i},D=function(){var t=[],r={writeByte:function(r){t.push(255&r)},writeShort:function(t){r.writeByte(t),r.writeByte(t>>>8)},writeBytes:function(t,e,n){e=e||0,n=n||t.length;for(var o=0;o<n;o+=1)r.writeByte(t[o+e])},writeString:function(t){for(var e=0;e<t.length;e+=1)r.writeByte(t.charCodeAt(e))},toByteArray:function(){return t},toString:function(){var r="";r+="[";for(var e=0;e<t.length;e+=1)e>0&&(r+=","),r+=t[e];return r+="]"}};return r},S=function(t){var r=t,e=0,n=0,o=0,i={read:function(){for(;o<8;){if(e>=r.length){if(0==o)return-1;throw"unexpected end of file./"+o}var t=r.charAt(e);if(e+=1,"="==t)return o=0,-1;t.match(/^\s$/)||(n=n<<6|a(t.charCodeAt(0)),o+=6)}var i=n>>>o-8&255;return o-=8,i}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return i},I=function(t,r,e){for(var n=function(t,r){var e=t,n=r,o=new Array(t*r),i={setPixel:function(t,r,n){o[r*e+t]=n},write:function(t){t.writeString("GIF87a"),t.writeShort(e),t.writeShort(n),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(e),t.writeShort(n),t.writeByte(0);var r=a(2);t.writeByte(2);for(var o=0;r.length-o>255;)t.writeByte(255),t.writeBytes(r,o,255),o+=255;t.writeByte(r.length-o),t.writeBytes(r,o,r.length-o),t.writeByte(0),t.writeString(";")}},a=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,i=u(),a=0;a<r;a+=1)i.add(String.fromCharCode(a));i.add(String.fromCharCode(r)),i.add(String.fromCharCode(e));var f,c,g,l=D(),h=(f=l,c=0,g=0,{write:function(t,r){if(t>>>r!=0)throw"length over";for(;c+r>=8;)f.writeByte(255&(t<<c|g)),r-=8-c,t>>>=8-c,g=0,c=0;g|=t<<c,c+=r},flush:function(){c>0&&f.writeByte(g)}});h.write(r,n);var s=0,v=String.fromCharCode(o[s]);for(s+=1;s<o.length;){var d=String.fromCharCode(o[s]);s+=1,i.contains(v+d)?v+=d:(h.write(i.indexOf(v),n),i.size()<4095&&(i.size()==1<<n&&(n+=1),i.add(v+d)),v=d)}return h.write(i.indexOf(v),n),h.write(e,n),h.flush(),l.toByteArray()},u=function(){var t={},r=0,e={add:function(n){if(e.contains(n))throw"dup key:"+n;t[n]=r,r+=1},size:function(){return r},indexOf:function(r){return t[r]},contains:function(r){return void 0!==t[r]}};return e};return i}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=D();n.write(a);for(var u=function(){var t=0,r=0,e=0,n="",o={},i=function(t){n+=String.fromCharCode(a(63&t))},a=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return o.writeByte=function(n){for(t=t<<8|255&n,r+=8,e+=1;r>=6;)i(t>>>r-6),r-=6},o.flush=function(){if(r>0&&(i(t<<6-r),t=0,r=0),e%3!=0)for(var o=3-e%3,a=0;a<o;a+=1)n+="="},o.toString=function(){return n},o}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return t}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||n>=57344?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}((function(){return qrcode}));
//# sourceMappingURL=/sm/26b4b0d0b1e283d6b3ec9857ac597d7a60c76ac17be1ef4c965f03086de426bb.map'''

LOGIN_TPL = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>limit 登录</title><style>{{ css|safe }}</style></head><body>
<div class="login-shell"><div class="login-card"><div class="logo"></div>
<h2>limit 登录</h2>
{% if err %}<div class="login-err">{{ err }}</div>{% endif %}
<form method="post" action="{{ P }}/login">
<div class="field"><label class="field-label">用户名</label><input type="text" name="username" autocomplete="off"></div>
<div class="field"><label class="field-label">密码</label><input type="password" name="password"></div>
<button class="btn-primary" type="submit">登 录</button>
</form></div></div></body></html>"""


DASH_TPL = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>limit</title><style>{{ css|safe }}</style><script>{{ qrlib|safe }}</script></head><body>
<div class="topbar">
  <div class="brand"><span class="logo"></span> limit · {{ t.name }}</div>
  <div style="display:flex;align-items:center;gap:12px;">
    <span class="tag mono">v1.10</span>
    <a class="logout-link" href="{{ P }}/logout">退出登录</a>
  </div>
</div>
<div class="wrap">

  <div class="panel" id="quota-panel">
    <div class="panel-head">
      <span>流量（总配额）</span>
      <span class="count"><span id="q-used">{{ used_h }}</span> / <span id="q-quota">{{ quota_h }}</span> · <span id="q-pct">{{ pct }}</span>%</span>
    </div>
    <div style="padding:0 20px 16px;">
      <div style="height:10px;background:#e0e0e0;border-radius:5px;overflow:hidden;margin-top:8px;">
        <div id="q-fill" style="height:100%;width:{{ pct }}%;background:linear-gradient(90deg,#2f6fed,#3fb950);"></div>
      </div>
    </div>
  </div>

  <div class="panel" id="vless-panel">
    <div class="panel-head">
      <span>vless 节点</span>
      <span class="count">{{ t.vless|length }}</span>
      <button type="button" class="btn-sm" onclick="openAddVless()">+ 节 点</button>
    </div>
    {% if t.vless %}
    <table>
      <tr><th>名称</th><th>端口</th><th>安全 · 网络</th><th>SNI</th><th>流量</th><th>状态</th><th>操作</th></tr>
      {% for n in t.vless %}
      <tr class="{{ 'paused' if (not n.enabled or t.exhausted) else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ n.remark or ('vless' ~ n.port) }}</span></td>
        <td class="mono">{{ n.port }}</td>
        <td>{{ ('REALITY' if n.security=='reality' else ('TLS' if n.security=='tls' else '无')) }} · {{ n.network|upper }}</td>
        <td class="mono" style="font-size:11.5px;">{{ n.sni or '—' }}</td>
        <td style="white-space:nowrap;"><span class="traffic-up">↑ {{ human(n.used_up|default(0)) }}</span><br><span class="traffic-down">↓ {{ human(n.used_down|default(0)) }}</span></td>
        <td>{% if n.enabled and not t.exhausted %}<span class="tag status-run">运行中</span>{% else %}<span class="tag status-pause">已暂停</span>{% endif %}</td>
        <td>
          <div class="row-actions">
            <button type="button" class="btn-sm-reset" data-l="{{ n.link|e }}" onclick="copyText(this.getAttribute('data-l'),'已复制链接')">复制链接</button>
            <button type="button" class="btn-sm-reset" data-l="{{ n.link|e }}" onclick="showQR(this.getAttribute('data-l'),'{{ (n.remark or ('vless' ~ n.port))|e }}')">二维码</button>
            <button type="button" class="btn-sm-reset" onclick="copyYaml('vless','{{ n.port }}')">导出YAML</button>
            <button type="button" class="btn-sm-reset" onclick="openSetSecret('vless','{{ n.port }}','{{ n.uuid }}')">uuid</button>
            <button type="button" class="btn-sm{{ '-resume' if (not n.enabled or t.exhausted) else '-warn' }}" onclick="postToggle('{{ P }}/toggle/vless/{{ n.port }}')">{{ '恢复' if (not n.enabled or t.exhausted) else '暂停' }}</button>
            <form method="post" action="{{ P }}/del/vless/{{ n.port }}" style="margin:0;" data-confirm="确定删除该节点？"><button type="submit" class="btn-sm-danger">删除</button></form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div class="empty-state">暂无 vless 节点</div>{% endif %}
  </div>

  <div class="panel" id="hy2-panel">
    <div class="panel-head">
      <span>Hysteria2 节点</span>
      <span class="count">{{ t.hy2|length }}</span>
      <button type="button" class="btn-sm" onclick="openAddHy2()">+ 节 点</button>
    </div>
    {% if t.hy2 %}
    <table>
      <tr><th>名称</th><th>端口</th><th>安全 · 网络</th><th>SNI</th><th>流量</th><th>状态</th><th>操作</th></tr>
      {% for h in t.hy2 %}
      <tr class="{{ 'paused' if (not h.enabled or t.exhausted) else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ h.name or ('hy2' ~ h.port) }}</span></td>
        <td class="mono">{{ h.port }}</td>
        <td>TLS · UDP</td>
        <td class="mono" style="font-size:11.5px;">{{ h.sni or '—' }}</td>
        <td style="white-space:nowrap;"><span class="traffic-up">↑ {{ human(h.used_up|default(0)) }}</span><br><span class="traffic-down">↓ {{ human(h.used_down|default(0)) }}</span></td>
        <td>{% if h.enabled and not t.exhausted %}<span class="tag status-run">运行中</span>{% else %}<span class="tag status-pause">已暂停</span>{% endif %}</td>
        <td>
          <div class="row-actions">
            <button type="button" class="btn-sm-reset" data-l="{{ h.link|e }}" onclick="copyText(this.getAttribute('data-l'),'已复制链接')">复制链接</button>
            <button type="button" class="btn-sm-reset" data-l="{{ h.link|e }}" onclick="showQR(this.getAttribute('data-l'),'{{ (h.name or ('hy2' ~ h.port))|e }}')">二维码</button>
            <button type="button" class="btn-sm-reset" onclick="copyYaml('hy2','{{ h.id }}')">导出YAML</button>
            <button type="button" class="btn-sm-reset" onclick="openSetSecret('hy2','{{ h.id }}','{{ h.password }}')">密码</button>
            <button type="button" class="btn-sm{{ '-resume' if (not h.enabled or t.exhausted) else '-warn' }}" onclick="postToggle('{{ P }}/toggle/hy2/{{ h.id }}')">{{ '恢复' if (not h.enabled or t.exhausted) else '暂停' }}</button>
            <form method="post" action="{{ P }}/del/hy2/{{ h.id }}" style="margin:0;" data-confirm="确定删除该节点？"><button type="submit" class="btn-sm-danger">删除</button></form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div class="empty-state">暂无 Hysteria2 节点</div>{% endif %}
  </div>

  <div class="panel" id="fwd-panel">
    <div class="panel-head">
      <span>中转</span>
      <span class="count">{{ t.fwd|length }}</span>
      <button type="button" class="btn-sm" onclick="openAddFwd()">+ 转 发</button>
    </div>
    {% if t.fwd %}
    <table>
      <tr><th>名称</th><th>本机端口</th><th>目标</th><th>协议</th><th>流量</th><th>状态</th><th>操作</th></tr>
      {% for f in t.fwd %}
      <tr class="{{ 'paused' if (not f.enabled or t.exhausted) else '' }}">
        <td><span class="mono" style="font-weight:600;">{{ f.name or ('fwd' ~ f.listen_port) }}</span></td>
        <td class="mono">{{ f.listen_port }}</td>
        <td class="mono" style="font-size:11.5px;">{{ f.target_ip }}:{{ f.target_port }}</td>
        <td class="mono">{% if f.tcp %}TCP{% endif %}{% if f.udp %}+UDP{% endif %}</td>
        <td style="white-space:nowrap;"><span class="traffic-up">↑ {{ human(f.used_up|default(0)) }}</span><br><span class="traffic-down">↓ {{ human(f.used_down|default(0)) }}</span></td>
        <td>{% if f.enabled and not t.exhausted %}<span class="tag status-run">运行中</span>{% else %}<span class="tag status-pause">已暂停</span>{% endif %}</td>
        <td>
          <div class="row-actions">
            <button type="button" class="btn-sm{{ '-resume' if (not f.enabled or t.exhausted) else '-warn' }}" onclick="postToggle('{{ P }}/toggle/fwd/{{ f.id }}')">{{ '恢复' if (not f.enabled or t.exhausted) else '暂停' }}</button>
            <form method="post" action="{{ P }}/del/fwd/{{ f.id }}" style="margin:0;" data-confirm="确定删除该中转？"><button type="submit" class="btn-sm-danger">删除</button></form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div class="empty-state">暂无中转</div>{% endif %}
  </div>

</div>

<div class="modal-backdrop" id="addVlessModal"><div class="modal-box" style="width:520px;">
  <h3>添加 vless 节点</h3>
  <form method="post" action="{{ P }}/add/vless">
    <div class="form-grid">
      <div class="full"><label>节点名称</label><input type="text" name="remark" id="avl-remark" required autocomplete="off" placeholder="vless1"></div>
      <div><label>端口</label><input type="number" name="port" id="avl-port" min="1" max="65535" required></div>
      <div class="full"><label>域名 / SNI</label>
        <div style="display:flex;gap:8px;">
          <input type="text" name="sni" id="avl-sni" autocomplete="off" placeholder="www.amazon.com" style="flex:1;min-width:0;">
          <button type="button" class="btn-sm-reset" onclick="document.getElementById('avl-sni').value=rndSite()" style="flex-shrink:0;margin-top:0;">换</button>
        </div>
      </div>
    </div>
    <div class="hint" style="margin-top:10px;">安全 REALITY · 网络 TCP；REALITY 密钥与 UUID 保存时自动生成。</div>
    <div class="modal-actions" style="margin-top:16px;"><button type="button" class="btn-cancel" onclick="closeModal('addVlessModal')">取消</button><button type="submit" class="btn-sm">保存节点</button></div>
  </form>
</div></div>

<div class="modal-backdrop" id="addHy2Modal"><div class="modal-box" style="width:520px;">
  <h3>添加 Hysteria2 节点</h3>
  <form method="post" action="{{ P }}/add/hy2">
    <div class="form-grid">
      <div class="full"><label>节点名称</label><input type="text" name="name" id="ahy-name" required autocomplete="off" placeholder="hy21"></div>
      <div><label>端口（UDP）</label><input type="number" name="port" id="ahy-port" min="1" max="65535" required></div>
      <div class="full"><label>域名 / SNI</label>
        <div style="display:flex;gap:8px;">
          <input type="text" name="sni" id="ahy-sni" autocomplete="off" placeholder="www.amazon.com" style="flex:1;min-width:0;">
          <button type="button" class="btn-sm-reset" onclick="document.getElementById('ahy-sni').value=rndSite()" style="flex-shrink:0;margin-top:0;">换</button>
        </div>
      </div>
    </div>
    <div class="hint" style="margin-top:10px;">证书固定用自签证书，客户端需开启「信任自签证书」；伪装网站自动取 SNI。</div>
    <div class="modal-actions" style="margin-top:16px;"><button type="button" class="btn-cancel" onclick="closeModal('addHy2Modal')">取消</button><button type="submit" class="btn-sm">保存节点</button></div>
  </form>
</div></div>

<div class="modal-backdrop" id="addFwdModal"><div class="modal-box" style="width:480px;">
  <h3>添加中转</h3>
  <form method="post" action="{{ P }}/add/fwd">
    <div class="form-grid">
      <div class="full"><label>名称</label><input type="text" name="name" id="afd-name" required autocomplete="off" placeholder="fwd1"></div>
      <div><label>本机端口</label><input type="number" name="port" id="afd-port" min="1" max="65535" required></div>
      <div><label>目标端口</label><input type="number" name="target_port" id="afd-tport" min="1" max="65535" required placeholder="443"></div>
      <div class="full"><label>目标 IP / 域名</label><input type="text" name="target_ip" id="afd-tip" required autocomplete="off" placeholder="1.2.3.4"></div>
    </div>
    <div class="hint" style="margin-top:10px;">纯转发，自动 TCP + UDP，只搬运字节不处理数据。</div>
    <div class="modal-actions" style="margin-top:16px;"><button type="button" class="btn-cancel" onclick="closeModal('addFwdModal')">取消</button><button type="submit" class="btn-sm">保存</button></div>
  </form>
</div></div>

<div class="modal-backdrop" id="secretModal"><div class="modal-box" style="width:480px;">
  <h3 id="ssTitle">修改 uuid / 密码</h3>
  <form method="post" id="ssForm">
    <div class="form-grid">
      <div class="full"><label>新 uuid / 密码</label>
        <div style="display:flex;gap:8px;">
          <input type="text" name="newpass" id="ss-pass" required autocomplete="off" spellcheck="false" style="flex:1;min-width:0;font-family:'SFMono-Regular',Consolas,monospace;">
          <button type="button" class="btn-sm-reset" onclick="genSecret()" style="flex-shrink:0;margin-top:0;">生成</button>
        </div>
      </div>
    </div>
    <div class="hint" style="margin-top:10px;" id="ssHint">vless 用 UUID 格式。</div>
    <div class="modal-actions" style="margin-top:16px;"><button type="button" class="btn-cancel" onclick="closeModal('secretModal')">取消</button><button type="submit" class="btn-sm">确认修改</button></div>
  </form>
</div></div>

<div class="modal-backdrop" id="qrModal"><div class="modal-box" style="width:380px;text-align:center;">
  <h3 id="qrTitle" style="text-align:left;">节点二维码</h3>
  <div id="qrBox" style="display:flex;justify-content:center;align-items:center;padding:8px 0;min-height:220px;"></div>
  <div class="mono" id="qrLink" style="font-size:11px;color:#8a929e;word-break:break-all;white-space:pre-wrap;max-height:80px;overflow:auto;text-align:left;background:#fafbfc;padding:8px;border-radius:6px;"></div>
  <div class="modal-actions" style="margin-top:16px;"><button type="button" class="btn-cancel" onclick="closeModal('qrModal')">关闭</button></div>
</div></div>

<script>
var P = "{{ P }}";
var SITES = {{ sites | tojson }};
function rndSite(){ return SITES[Math.floor(Math.random()*SITES.length)]; }
function rndPort(kind){
  var r = kind==='hy2' ? [30000,30999] : (kind==='fwd' ? [22000,29999] : [21000,21999]);
  return r[0] + Math.floor(Math.random()*(r[1]-r[0]+1));
}
function showToast(msg, ok){
  if(!window._toastEl){ window._toastEl = document.createElement('div'); window._toastEl.id = 'async-toast'; document.body.appendChild(window._toastEl); }
  window._toastEl.textContent = msg;
  window._toastEl.classList.add('show');
  if(ok === false){ window._toastEl.classList.add('err'); } else { window._toastEl.classList.remove('err'); }
  if(window._toastTimer) clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(function(){ if(window._toastEl) window._toastEl.classList.remove('show'); }, 2500);
}
function fbCopy(txt){
  var ta = document.createElement('textarea'); ta.value = txt; ta.style.position = 'fixed'; ta.style.top = '-1000px';
  document.body.appendChild(ta); ta.select(); try{ document.execCommand('copy'); }catch(_){} document.body.removeChild(ta);
}
function copyText(txt,msg){
  function done(){ showToast(msg || '已复制'); }
  try{
    if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done).catch(function(){ fbCopy(txt); done(); }); }
    else { fbCopy(txt); done(); }
  }catch(e){ fbCopy(txt); done(); }
}
function showQR(text, title){
  document.getElementById('qrTitle').textContent = title || '节点二维码';
  document.getElementById('qrLink').textContent = text || '';
  var box = document.getElementById('qrBox');
  box.innerHTML = '';
  try {
    var qr = qrcode(0, 'L');
    qr.addData(text || '');
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
  } catch (e) { box.innerHTML = '<div class="empty-state">生成二维码失败</div>'; }
  openModal('qrModal');
}
async function copyYaml(kind, key){
  try {
    var r = await fetch(P + '/yaml/' + kind + '/' + key);
    if(!r.ok){ showToast('读取失败', false); return; }
    var txt = await r.text();
    try { await navigator.clipboard.writeText(txt); } catch(e){ fbCopy(txt); }
    showToast('已复制YAML');
  } catch(e){ showToast('读取失败', false); }
}
function openModal(id){ document.getElementById(id).classList.add('open'); }
function closeModal(id){ document.getElementById(id).classList.remove('open'); }
function openAddVless(){
  document.getElementById('addVlessModal').querySelector('form').reset();
  document.getElementById('avl-port').value = rndPort('vless');
  document.getElementById('avl-sni').value = rndSite();
  openModal('addVlessModal');
}
function openAddHy2(){
  document.getElementById('addHy2Modal').querySelector('form').reset();
  document.getElementById('ahy-port').value = rndPort('hy2');
  document.getElementById('ahy-sni').value = rndSite();
  openModal('addHy2Modal');
}
function openAddFwd(){
  document.getElementById('addFwdModal').querySelector('form').reset();
  document.getElementById('afd-port').value = rndPort('fwd');
  openModal('addFwdModal');
}
function genSecret(){
  var v = (window.crypto && crypto.randomUUID) ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(cc){ var r=Math.random()*16|0; return (cc==='x'?r:(r&0x3|0x8)).toString(16); });
  document.getElementById('ss-pass').value = v;
}
function openSetSecret(kind,key,val){
  document.getElementById('ssTitle').textContent = (kind==='vless' ? '修改 vless UUID' : '修改 hy2 密码');
  document.getElementById('ssHint').textContent = (kind==='vless' ? 'UUID 格式；点「生成」随机生成。' : '点「生成」随机生成密码。');
  document.getElementById('ss-pass').value = val || '';
  document.getElementById('ssForm').setAttribute('action', P + '/setsecret/' + kind + '/' + key);
  openModal('secretModal');
}
function postToggle(url){
  fetch(url,{method:'POST',credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){
    if(d && d.ok){ showToast(d.msg || '操作成功'); setTimeout(function(){ location.reload(); }, 700); }
    else { alert((d && d.msg) || '操作失败'); }
  }).catch(function(){ showToast('网络错误', false); });
}
function pollTraffic(){
  fetch(P + '/traffic').then(function(r){return r.json()}).then(function(d){
    var u=document.getElementById('q-used'); if(!u){return;}
    u.textContent=d.used_h;
    document.getElementById('q-quota').textContent=d.quota_h;
    document.getElementById('q-pct').textContent=d.pct;
    document.getElementById('q-fill').style.width=d.pct+'%';
  }).catch(function(){});
}
setInterval(pollTraffic,5000);
{% if flash_msg %}showToast({{ flash_msg | tojson }}, {{ 'true' if flash_ok else 'false' }});{% endif %}
document.addEventListener('submit',function(e){
  var f=e.target;
  if(f && f.getAttribute && f.getAttribute('data-confirm')){ if(!confirm(f.getAttribute('data-confirm'))){ e.preventDefault(); } }
},true);
</script>
</body></html>"""


def _page_login(pt, err=None):
    return render_template_string(LOGIN_TPL, css=BASE_CSS, P="/" + pt, err=err)


@app.route("/<pt>/")
def index(pt):
    t = _tenant_by_req(pt)
    if not t:
        return "not found", 404
    if not _authed(t["id"]):
        return redirect("/%s/login" % pt)
    session["t:" + t["id"]] = time.time()
    for n in t.get("vless", []):
        n["link"] = vless_link(n)
    for h in t.get("hy2", []):
        h["link"] = hy2_link(h)
    used = int(t.get("used_up", 0)) + int(t.get("used_down", 0))
    q = int(t.get("quota_bytes", 0) or 0)
    pct = (min(100, int(used * 100 / q)) if q else 0)
    flash_msg, flash_ok = _take_flash()
    return render_template_string(DASH_TPL, css=BASE_CSS, t=t, P="/" + pt,
                                  used_h=human(used), quota_h=human(q), pct=pct, sites=SITES,
                                  qrlib=QRLIB, human=human, flash_msg=flash_msg, flash_ok=flash_ok)


@app.route("/<pt>/login", methods=["GET", "POST"])
def login(pt):
    t = _tenant_by_req(pt)
    if not t:
        return "not found", 404
    ip = request.remote_addr or "?"
    err = None
    if request.method == "POST":
        left = _lk_left(t["id"], ip)
        if left > 0:
            err = "已锁定，剩余 %d 分钟" % (left // 60)
        else:
            u = (request.form.get("username") or "").strip()
            p = request.form.get("password") or ""
            if u == t.get("user") and sha256(p) == t.get("pass_hash"):
                _lk_clear(t["id"], ip)
                session["auth:" + t["id"]] = True
                session.permanent = True
                session["t:" + t["id"]] = time.time()
                return redirect("/%s/" % pt)
            _lk_fail(t["id"], ip); err = "用户名或密码错误"
    return _page_login(pt, err)


@app.route("/<pt>/logout")
def logout(pt):
    t = _tenant_by_req(pt)
    if t:
        session.pop("auth:" + t["id"], None)
    return redirect("/%s/login" % pt)


@app.route("/<pt>/traffic")
def traffic(pt):
    t = _tenant_by_req(pt)
    if not t or not _authed(t["id"]):
        return jsonify({"used_h": "-", "quota_h": "-", "pct": 0}), 403
    used = int(t.get("used_up", 0)) + int(t.get("used_down", 0))
    q = int(t.get("quota_bytes", 0) or 0)
    return jsonify({"used_h": human(used), "quota_h": human(q),
                    "pct": (min(100, int(used * 100 / q)) if q else 0)})


def _mutate(tid, fn):
    with _lock():
        ts = load_tenants()
        t = next((x for x in ts if x.get("id") == tid), None)
        if t is None:
            return None
        fn(t)
        save_tenants(ts)
        return t


def _apply():
    apply_all(load_tenants())


@app.route("/<pt>/toggle/<kind>/<key>", methods=["POST"])
def toggle(pt, kind, key):
    t = _need(pt)
    if not t:
        return jsonify({"ok": False, "msg": "未登录"}), 403
    if t.get("exhausted"):
        return jsonify({"ok": False, "msg": "流量包已耗尽，服务已停用"})
    def fn(x):
        n = _find_node(x, kind, key)
        if n is not None:
            n["enabled"] = not n.get("enabled", True)
    res = _mutate(t["id"], fn); _apply()
    n = _find_node(res, kind, key) if res else None
    running = bool(n.get("enabled", True)) if n else False
    return jsonify({"ok": True, "msg": "已恢复" if running else "已暂停"})


@app.route("/<pt>/del/<kind>/<key>", methods=["POST"])
def del_node(pt, kind, key):
    t = _need(pt)
    if not t:
        return redirect("/%s/login" % pt)
    def fn(x):
        x["retired_up"] = int(x.get("retired_up", 0))
        x["retired_down"] = int(x.get("retired_down", 0))
        def _retire(item):
            x["retired_up"] += int(item.get("used_up", 0))
            x["retired_down"] += int(item.get("used_down", 0))
        if kind == "vless":
            for n in list(x.get("vless", [])):
                if str(n["port"]) == str(key):
                    _retire(n)
                    ufw_delete(int(n["port"]), udp=False); x["vless"].remove(n)
        elif kind == "hy2":
            for h in list(x.get("hy2", [])):
                if h["id"] == key:
                    _retire(h)
                    ufw_delete(int(h["port"]), udp=True); x["hy2"].remove(h)
        elif kind == "fwd":
            for f in list(x.get("fwd", [])):
                if f["id"] == key:
                    _retire(f)
                    ufw_delete(int(f["listen_port"]), udp=f.get("udp")); x["fwd"].remove(f)
    _mutate(t["id"], fn); _apply()
    _set_flash("已删除")
    return redirect("/%s/" % pt)


@app.route("/<pt>/add/vless", methods=["POST"])
def add_vless(pt):
    t = _need(pt)
    if not t:
        return redirect("/%s/login" % pt)
    ts = load_tenants()
    try:
        port = check_port(ts, request.form.get("port"), udp=False, rng=VLESS_RANGE)
    except Exception as e:
        _set_flash(str(e), False); return redirect("/%s/" % pt)
    rm = (request.form.get("remark") or "").strip() or ("vless%d" % port)
    sni = (request.form.get("sni") or "").strip() or HY2_SNI
    security = "reality"
    priv = pub = ""
    try:
        priv, pub = gen_reality_keys()
    except Exception:
        security = "none"
    node = {"port": port, "remark": rm, "security": security, "network": "tcp", "sni": sni,
            "dest": sni + ":443", "uuid": str(uuid.uuid4()), "enabled": True,
            "last_up": 0, "last_down": 0, "used_up": 0, "used_down": 0}
    if security == "reality":
        node["reality_private"] = priv
        node["reality_public"] = pub
        node["short_id"] = secrets.token_hex(8)
    _mutate(t["id"], lambda x: x.setdefault("vless", []).append(node))
    ufw_allow(port, False); _apply()
    _set_flash("节点已添加")
    return redirect("/%s/" % pt)


@app.route("/<pt>/add/hy2", methods=["POST"])
def add_hy2(pt):
    t = _need(pt)
    if not t:
        return redirect("/%s/login" % pt)
    ts = load_tenants()
    try:
        port = check_port(ts, request.form.get("port"), udp=True, rng=HY2_RANGE)
    except Exception as e:
        _set_flash(str(e), False); return redirect("/%s/" % pt)
    name = (request.form.get("name") or "").strip() or ("hy2%d" % port)
    sni = (request.form.get("sni") or "").strip() or HY2_SNI
    used_stats = set()
    for t2 in ts:
        for h2 in t2.get("hy2", []):
            try:
                used_stats.add(int(str(h2.get("listen", "")).rsplit(":", 1)[-1]))
            except Exception:
                pass
    sp = port + 1000
    for _ in range(1000):
        if sp not in used_stats and _port_free(sp, udp=False):
            break
        sp += 1
        if sp > 31999:
            sp = 31000
    nid = uuid.uuid4().hex[:6]
    node = {"id": nid, "name": name, "port": port, "sni": sni, "masquerade": "https://" + sni,
            "listen": "127.0.0.1:%d" % sp,
            "secret": secrets.token_hex(16), "password": uuid.uuid4().hex, "enabled": True,
            "last_up": 0, "last_down": 0, "used_up": 0, "used_down": 0}
    _mutate(t["id"], lambda x: x.setdefault("hy2", []).append(node))
    ufw_allow(port, udp=True); _apply()
    _set_flash("节点已添加")
    return redirect("/%s/" % pt)


@app.route("/<pt>/add/fwd", methods=["POST"])
def add_fwd(pt):
    t = _need(pt)
    if not t:
        return redirect("/%s/login" % pt)
    tip = (request.form.get("target_ip") or "").strip()
    tp = (request.form.get("target_port") or "").strip()
    if not tip or not tp.isdigit():
        _set_flash("目标 IP / 端口必填", False); return redirect("/%s/" % pt)
    ts = load_tenants()
    try:
        port = check_port(ts, request.form.get("port"), udp=True, rng=FWD_RANGE)
    except Exception as e:
        _set_flash(str(e), False); return redirect("/%s/" % pt)
    name = (request.form.get("name") or "").strip() or ("fwd%d" % port)
    fid = uuid.uuid4().hex[:8]
    rule = {"id": fid, "name": name, "listen_port": port, "target_ip": tip, "target_port": int(tp),
            "tcp": True, "udp": True, "enabled": True,
            "last_up": 0, "last_down": 0, "used_up": 0, "used_down": 0}
    _mutate(t["id"], lambda x: x.setdefault("fwd", []).append(rule))
    ufw_allow(port, udp=True); _apply()
    _set_flash("中转已添加")
    return redirect("/%s/" % pt)


@app.route("/<pt>/setsecret/<kind>/<key>", methods=["POST"])
def set_secret(pt, kind, key):
    t = _need(pt)
    if not t:
        return redirect("/%s/login" % pt)
    val = (request.form.get("newpass") or "").strip()
    if val:
        def fn(x):
            n = _find_node(x, kind, key)
            if n is None:
                return
            if kind == "vless":
                n["uuid"] = val
            elif kind == "hy2":
                n["password"] = val
        _mutate(t["id"], fn); _apply()
    _set_flash("已修改")
    return redirect("/%s/" % pt)


@app.route("/<pt>/yaml/<kind>/<key>")
def export_yaml(pt, kind, key):
    t = _need(pt)
    if not t or kind not in ("vless", "hy2"):
        return "not found", 404
    n = _find_node(t, kind, key)
    if n is None:
        return "not found", 404
    lines = ["proxies:"]
    if kind == "vless":
        sec = n.get("security", "none")
        nm = (n.get("remark") or ("vless%d" % n["port"])).replace(":", "-")
        lines += ["  - name: \"%s\"" % nm, "    type: vless", "    server: %s" % SERVER_IP,
                  "    port: %d" % int(n["port"]), "    uuid: %s" % n["uuid"],
                  "    network: %s" % n.get("network", "tcp"), "    udp: true",
                  "    tls: %s" % ("true" if sec in ("reality", "tls") else "false")]
        if sec == "reality":
            lines += ["    servername: %s" % n.get("sni", ""), "    client-fingerprint: chrome",
                      "    reality-opts:", "      public-key: %s" % n.get("reality_public", ""),
                      "      short-id: %s" % n.get("short_id", "")]
            if _vless_flow(n):
                lines += ["    flow: %s" % _vless_flow(n)]
        elif sec == "tls":
            lines += ["    servername: %s" % n.get("sni", "")]
    else:
        nm = (n.get("name") or ("hy2%d" % n["port"])).replace(":", "-")
        lines += ["  - name: \"%s\"" % nm, "    type: hysteria2", "    server: %s" % SERVER_IP,
                  "    port: %d" % int(n["port"]), "    password: %s" % n.get("password", ""),
                  "    sni: %s" % n.get("sni", ""), "    skip-cert-verify: true"]
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=%s-%s.yaml" % (kind, key)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8099)

