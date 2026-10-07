"""Hive — traffic accounting helpers for the limit panel.

Small read-only helpers that query the per-tenant Xray stats API and each
tenant's Hysteria2 traffic-stats endpoint; the limit collector does the actual
accumulation.

This is the first version — see README.md.
"""

import json, subprocess, urllib.request


def _stats(api_server):
    r = subprocess.run(["xray", "api", "statsquery", "--server=%s" % api_server],
                       capture_output=True, text=True, timeout=6)
    return json.loads(r.stdout or "{}").get("stat", []) or []


def get_xray_inbound_map(api_server):
    """Return {tag: {"up":int,"down":int}} for inbound (dokodemo/中转) tags."""
    out = {}
    try:
        for s in _stats(api_server):
            parts = s.get("name", "").split(">>>")
            if len(parts) != 4 or parts[0] != "inbound":
                continue
            e = out.setdefault(parts[1], {"up": 0, "down": 0})
            v = int(s.get("value", 0) or 0)
            if parts[3] == "uplink":
                e["up"] = v
            elif parts[3] == "downlink":
                e["down"] = v
    except Exception:
        pass
    return out


def get_xray_user_map(api_server):
    """Return {email: {"up":int,"down":int}} per vless client (user stats)."""
    out = {}
    try:
        for s in _stats(api_server):
            parts = s.get("name", "").split(">>>")
            if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
                continue
            e = out.setdefault(parts[1], {"up": 0, "down": 0})
            v = int(s.get("value", 0) or 0)
            if parts[3] == "uplink":
                e["up"] = v
            elif parts[3] == "downlink":
                e["down"] = v
    except Exception:
        pass
    return out


def get_hy2_users(nodes):
    """nodes: [{"id","listen","secret"}]; returns {node_id: {user: {"up","down"}}}."""
    out = {}
    for n in nodes:
        try:
            req = urllib.request.Request("http://%s/traffic" % n["listen"],
                                         headers={"Authorization": n.get("secret", "")})
            with urllib.request.urlopen(req, timeout=5) as resp:
                d = json.loads(resp.read())
            m = {}
            for name, v in (d or {}).items():
                if isinstance(v, dict):
                    m[name] = {"up": int(v.get("tx", 0) or 0), "down": int(v.get("rx", 0) or 0)}
            out[n["id"]] = m
        except Exception:
            pass
    return out

