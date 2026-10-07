# Hive

> **一台服务器，多个互不可见的租户。** 面向转售/多租户的 Xray（VLESS/REALITY）+ Hysteria2 面板，内置管理员子面板、按租户总流量配额，以及进程级隔离。

> ⚠️ **这是初版。** 还非常粗糙：功能不全、文档简略、肯定还有没发现的 bug。
> 请把它当作一个起点而不是成品。欢迎提 Issue 和 PR。

[English](README.md)

---

## 为什么是 Hive

通用面板（3x-ui、Marzban）都是**单管理员**或**共享核心的多用户**：所有管理员/客户端跑在同一个 Xray 进程、同一份配置里。Hive 面向**转售 / 多租户**场景：把一台服务器切成**多个互不可见的租户**，每个租户拥有**独立面板、独立节点、独立总配额**。

- **3x-ui** — 单管理员；“多节点”= 管理**别的** 3x-ui 实例。
- **Marzban** — 共享 Xray 核心、以“用户”为中心、多管理员（WIP）。
- **Hive** — 每个租户**独立的 Xray/Hysteria2 实例** + 独立 Web 面板（独立端口+路径）+ **进程级隔离**（systemd 沙箱 + 非 root + 窄接口 root helper）+ **总配额**（达额自动停用）。

## 功能

- **主面板（admin）**：系统状态、VLESS（REALITY/TLS/WS/gRPC）节点、Hysteria2 节点、中转、终端用户管理、按用户流量、ufw 防火墙卡片、二维码 / 分享链接 / Clash-YAML 导出。
- **Limit 多租户面板**：每个租户得到**独立面板**（独立随机端口 + 随机路径），管理**自己的** VLESS/Hysteria2/中转节点与客户端，带**总流量配额**。
- **配额**：租户达总配额后其全部节点自动停用。
- **总开关**：一键暂停/恢复**全部** limit 服务。
- **节点控制**：所有节点（含安装时自动创建的两个）都可以暂停和删除。
- **HTTPS 面板**：两个面板都用自动生成的自签证书提供 TLS；浏览器会提示一次证书不受信任。
- **隔离优先**：独立进程、systemd 强化（暴露分低至 **1.9–4.0**）、租户 Web 进程以**非 root** 运行，特权动作只经**窄接口 root helper**。

## 安装

一行命令，在全新的 **Debian/Ubuntu** VPS（root）上执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh)
```

会安装 Xray-core、Hysteria2、主面板和多租户（limit）面板，并打印 `https://` 地址、随机路径与生成的账号密码。证书是自签的，浏览器会提示一次不受信任，这是预期的。

再次执行同一条命令即可原地更新（节点、用户、租户、端口、路径与账号密码都会保留）；也可以用它安装的快捷命令：

```bash
hive
```

卸载：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sebastian7577/hive/main/install.sh) uninstall
```

## 安全说明

- **账号密码随机且哈希存储。** 安装时随机生成用户名+密码，只在 `/opt/xray-viewer/panel_auth.json`（0600）里保存加盐 **PBKDF2** 哈希，绝不写进源码；可在面板内修改密码。
- **面板走 HTTPS**（自签证书；`Secure` cookie + HSTS），口令不再明文传输。
- **不重置防火墙。** 安装脚本只**追加**规则：始终保留它探测到的 SSH 端口（来自 `sshd_config` 和当前会话），并放行 `443` 与面板端口；只有显式传 `--reset-firewall` 才会清空 ufw。
- **Hysteria2 固定版本并校验。** 二进制取自官方 `apernet/hysteria`，并按脚本内置的 SHA256 校验。
- **租户隔离**：每个租户跑在独立的 systemd 沙箱里的 Xray/Hysteria2 实例；租户 Web 进程非 root，只能通过 `limit-helper` 操作自己的单元/端口。

## 架构

```
             ┌────────────────────────── 主面板 (xray-viewer, root, 沙箱) ──────────────────────────┐
 浏览器 ───► │  管理主 xray + hysteria2 + 中转 + 用户 + ufw · “limit用户”卡片                          │
             └───────────────┬───────────────────────────────────────────────┬─────────────────────┘
                             │ 共享数据 tenants.json (flock)                   │ 开关（启停）
                             ▼                                                 ▼
             ┌──────────── limit 面板 (limit-viewer, 用户 limitpanel, 沙箱) ─────────────┐
 租户 ─────► │  按“请求端口 + 路径”区分租户 · 写配置                                        │
 (独立端口)  │        │                                                                     │
             └────────┼─────────────────────────────────────────────────────────────────────┘
                      │ 特权调用（systemctl / ufw / iptables）经 unix socket
                      ▼
             ┌──────── limit-helper (root, 窄白名单接口) ────────┐
             └───────────────────────────────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   limit-xray (nobody)      limit-hysteria@<节点> (hysteria)   ← 每租户独立实例
```

## 隔离一览

`systemd-analyze security` 暴露分（越低越好）：

| 单元 | 之前 | Hive |
|---|---|---|
| xray（主） | 9.6 UNSAFE | **2.2 OK** |
| xray-viewer（主面板） | 9.6 | **4.0 OK** |
| limit-viewer | 7.8 EXPOSED | **3.5 OK**（非 root） |
| limit-xray | 7.2 | **2.2 OK** |
| hysteria 节点 | — | **1.9 OK** |

## 依赖

- Debian/Ubuntu、root、systemd。
- Python 3 + gunicorn + flask（脚本自动安装）。
- Xray-core 与 Hysteria2（脚本自动安装）。

## 许可

[MIT](LICENSE)
