import json, os, subprocess, fcntl, contextlib, urllib.request

TRAFFIC_PATH = "/usr/local/etc/xray/traffic_totals.json"
LOCK_PATH = "/usr/local/etc/xray/.traffic.lock"
API_SERVER = "127.0.0.1:10085"

HY2_NODES_PATH = "/usr/local/etc/xray/hy2_nodes.json"

@contextlib.contextmanager
def _locked():
    """File lock so the collector process and web app never write
    traffic_totals.json at the same time and corrupt it."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    with open(LOCK_PATH, "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)

def get_traffic_map():
    """One-shot query of xray's live in-memory stats. Can block briefly on
    subprocess — only ever called from the collector process now, never
    from a web request."""
    result = {}
    try:
        out = subprocess.run(
            ["xray", "api", "statsquery", f"--server={API_SERVER}"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(out.stdout)
        for stat in data.get("stat", []):
            name = stat.get("name", "")
            value = int(stat.get("value", 0))
            parts = name.split(">>>")
            if len(parts) != 4:
                continue
            direction = parts[3]
            if parts[0] == "user":
                email = parts[1]
                result.setdefault(email, {"up": 0, "down": 0})
                if direction == "uplink":
                    result[email]["up"] = value
                elif direction == "downlink":
                    result[email]["down"] = value
            elif parts[0] == "inbound" and parts[1].startswith("fwd-fwd-"):
                rest = parts[1][len("fwd-"):]
                if rest.endswith("-tcp"):
                    fwd_id = rest[:-len("-tcp")]
                elif rest.endswith("-udp"):
                    fwd_id = rest[:-len("-udp")]
                else:
                    continue
                key = "fwd:" + fwd_id
                result.setdefault(key, {"up": 0, "down": 0})
                if direction == "uplink":
                    result[key]["up"] += value
                elif direction == "downlink":
                    result[key]["down"] += value
    except Exception:
        pass
    return result

def _hy2_nodes():
    """读面板管理的 hy2 节点清单，返回 [{base, secret, users}]。"""
    try:
        with open(HY2_NODES_PATH) as f:
            data = json.load(f)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for n in data:
        if not isinstance(n, dict):
            continue
        st = n.get("stats") or {}
        listen = st.get("listen")
        secret = st.get("secret")
        if not listen or not secret:
            continue
        users = [u.get("name") for u in (n.get("users") or [])
                 if isinstance(u, dict) and u.get("name")]
        out.append({"base": "http://%s/traffic" % listen, "secret": secret, "users": users})
    return out

def get_hy2_traffic_map():
    """查询所有 Hysteria2 节点的 Traffic Stats API 并按用户名聚合。
    不带 clear 参数读自己的累计计数器，走跟 xray 一样的 delta 逻辑，
    hysteria-server 重启导致计数器归零时也不会算错（rollover 保护复用同一套代码）。"""
    result = {}
    for node in _hy2_nodes():
        try:
            req = urllib.request.Request(
                node["base"],
                headers={"Authorization": node["secret"]}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            for name, v in data.items():
                if isinstance(v, dict) and isinstance(name, str):
                    result.setdefault(name, {"up": 0, "down": 0})
                    result[name]["up"] += int(v.get("tx", 0))
                    result[name]["down"] += int(v.get("rx", 0))
        except Exception:
            pass
    return result

def _load_store_nolock():
    if not os.path.exists(TRAFFIC_PATH):
        return {}
    try:
        with open(TRAFFIC_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_store_nolock(store):
    tmp_path = TRAFFIC_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, TRAFFIC_PATH)

def read_totals():
    """Fast, read-only path for the web app. No subprocess call."""
    with _locked():
        store = _load_store_nolock()
    return {email: {"up": v.get("total_up", 0), "down": v.get("total_down", 0)}
            for email, v in store.items()}

def accumulate_once():
    """Queries xray live (and Hysteria2's stats API) and folds the delta
    into the persistent totals. Called by the background collector on a
    timer, and once synchronously right before an xray restart so no
    traffic is lost at that boundary."""
    raw = get_traffic_map()
    raw.update(get_hy2_traffic_map())
    with _locked():
        store = _load_store_nolock()
        changed = False
        for email, vals in raw.items():
            entry = store.setdefault(email, {
                "total_up": 0, "total_down": 0,
                "last_raw_up": 0, "last_raw_down": 0,
            })
            for direction, total_key, last_key in (
                ("up", "total_up", "last_raw_up"),
                ("down", "total_down", "last_raw_down"),
            ):
                raw_val = vals.get(direction, 0)
                last_raw = entry.get(last_key, 0)
                delta = (raw_val - last_raw) if raw_val >= last_raw else raw_val
                if delta:
                    entry[total_key] = entry.get(total_key, 0) + delta
                    changed = True
                entry[last_key] = raw_val
        if changed:
            _save_store_nolock(store)
    return raw

def remove_entry(email):
    if not email:
        return
    with _locked():
        store = _load_store_nolock()
        if email in store:
            del store[email]
            _save_store_nolock(store)

def reset_entry(email):
    if not email:
        return
    with _locked():
        store = _load_store_nolock()
        entry = store.get(email)
        if entry is not None:
            entry["total_up"] = 0
            entry["total_down"] = 0
            _save_store_nolock(store)

