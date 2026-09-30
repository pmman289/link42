# Link42 生产可用性审计报告

> 审计对象：<https://github.com/pmman289/link42>（`main` 分支，最新提交 `584c840`，后端 `0.2.1` / 前端 `0.6.21`）
> 审计日期：2026-09-30
> 审计范围：主控后端（FastAPI）、Web 前端（React/Vite）、节点 Agent、共享包、部署/构建/CI 脚本
> 审计方法：逐文件读源码；本地跑全量单测、前端类型检查、单测和构建；用 FastAPI TestClient 模拟 Agent 跑完整业务流程，并逐条验证增删改查接口

---

## 0. 结论速览

| 维度 | 结论 |
|---|---|
| 主流程能否跑通 | ✅ **能跑通**：添加节点 → Agent 注册/心跳 → 创建受管连接（WireGuard/GRE）→ Agent 拉取任务 → 回报结果 → 状态流转 → 启停 → 删除；导入扫描 → 导入 → 接管 → 确认变更计划。全部实测通过 |
| 增删改查完整性 | ⚠️ 基本齐全，但有 **3 处后端逻辑缺陷**（删除后仍会下发旧任务；删除受管单边返回 500；受管对端可被误删），前端有 **2 处功能入口缺失**（删除对端、编辑 Looking Glass Token） |
| 安全基线 | ⚠️ 基础扎实：Argon2id、token 只存哈希且用常量时间比较、AES-GCM 字段加密、HttpOnly+SameSite Cookie、CSRF 头、CSP，没有 `dangerouslySetInnerHTML`。但仍有 **1 个高危**（WireGuard 配置可换行注入，导致节点 root 执行命令）、**1 个高危**（udp2raw 二进制下载不校验完整性）和 **1 处明文密码写日志** |
| 并发/幂等 | ⚠️ 任务领取、变更计划确认、任务结果回报都是“先检查后执行”，没有原子保护，可能重复执行 |
| 性能 | ⚠️ 链路监测样本一次全量加载、不分页；列表接口有 N+1 查询；任务、查询记录没有保留期 |
| 前端 | ⚠️ 功能覆盖较好，前端调用的接口都能在后端找到（0 处越界）。问题集中在：7362 行单文件、1.5 MB 单包、新建节点的令牌只在 Toast 里闪 3.8 秒、部分删除没有二次确认、长文本溢出、可访问性 |
| 工程化 | ⚠️ 后端 `main.py` 6394 行；CI 不跑 pytest；Python 依赖没有锁定；Docker 镜像以 root 运行、没有 HEALTHCHECK、用的是 `npm install` |

**上线前必须修（P0）**：见 §1 优先级总表，共 8 项。都是局部改动，只要按文中“兼容性”说明做，不会破坏现有流程。

---

## 1. 验证记录与优先级总表

### 1.1 本地验证结果

| 检查项 | 命令 | 结果 |
|---|---|---|
| 后端/Agent 单测 | `python -m pytest -q` | 267 通过 / 9 失败。**9 个失败都和 Windows 平台有关**（`os.chown` 不存在、没有 systemd/UCI、路径分隔符、文件被占用），在 Linux CI 上应能通过。其中 `test_sqlite_upgrade_backup_keeps_single_file` 的 `WinError 32` 反映了**真实的连接未关闭问题**，见 B-07 |
| 前端类型检查 | `tsc --noEmit` | ✅ 通过 |
| 前端单测 | `vitest run` | ✅ 20/20 |
| 前端构建 | `vite build` | ✅ 通过，但出现单 chunk **1,528 KB**（gzip 448 KB）警告 |
| 业务流程 E2E（TestClient 模拟 Agent） | 自编脚本 | ✅ 主流程全部跑通；发现 3 处缺陷（F-01~F-03） |

### 1.2 优先级总表

| 编号 | 级别 | 优先级 | 问题 | 影响现有流程风险 |
|---|---|---|---|---|
| S-01 | 高 | P0 | 初始管理员密码明文写入日志 | 无 |
| S-02 | 高 | P0 | WireGuard 渲染不过滤换行，单值字段可注入 `PostUp` 导致节点 root RCE | 低（只拒绝含控制字符的值） |
| S-03 | 高 | P0 | udp2raw 二进制下载接口免鉴权，且下载后不校验 sha256，最终以 root 运行 | 中（需同步发布流程） |
| F-01 | 高 | P0 | 删除 WireGuard 配置不取消待执行任务，Agent 会把已删配置写回节点 | 低 |
| F-02 | 高 | P0 | 用通用接口删除受管链路单边 → 外键错误 500 | 低 |
| F-03 | 高 | P0 | 受管链路的对端可被 `DELETE .../peer` 删掉，链路被破坏 | 低 |
| B-01 | 中 | P0 | Agent 任务领取非原子，可能重复执行 | 低 |
| B-02 | 中 | P0 | 变更计划确认非原子，可能重复部署 | 低 |
| S-04 | 中 | P1 | 登录限流的“纯账号维度”可被远程利用锁死唯一管理员 | 低 |
| S-05 | 中 | P1 | Agent 失败结果上报完整 traceback | 无 |
| S-06 | 中 | P1 | CORS 放开全部方法和头并允许凭据 | 低 |
| B-03 | 中 | P1 | 任务结果上报不校验终态，重复上报会再次触发副作用 | **中（需兼容 Agent 重试）** |
| B-04 | 中 | P1 | GRE 启停/中间件安装没有任务去重 | 低 |
| B-05 | 中 | P1 | Looking Glass 分页在 LIMIT 之后才按 `online` 过滤，会丢数据 | 低 |
| B-06 | 中 | P1 | 节点 PATCH 实际是 PUT 语义；LinkMonitor/Settings 同样问题 | 低（前端全量提交） |
| B-07 | 中 | P1 | SQLite 备份用 `with sqlite3.connect()` 不会关闭连接 | 无 |
| B-08 | 中 | P1 | 接口名主控允许 32 位，Agent/Linux 只允许 15 位；节点 IP 字段没有校验 | **中（存量数据）** |
| B-09 | 中 | P1 | 对端长期离线时，连接/节点无法删除（死锁） | 低（新增可选 force） |
| B-10 | 中 | P2 | 对“仅导入观察”的配置执行 plan-apply 会生成无法确认的空计划 | 低 |
| P-01 | 高 | P1 | 监测样本全量加载、无上限；30 天窗口可达数十万行 | 中（图表点数变化） |
| P-02 | 中 | P2 | 列表/拓扑接口有 N+1 查询 | 无 |
| P-03 | 中 | P2 | AgentTask / LookingGlassQuery 没有保留期，无限增长 | 低 |
| FE-01 | 高 | P1 | 新建节点的 Agent 令牌只在 3.8 秒 Toast 中出现一次 | 无 |
| FE-02 | 中 | P1 | 缺少“删除对端”“编辑 LG Token”入口 | 无 |
| FE-03 | 中 | P1 | 删除链路监测/端口台账条目没有二次确认；端口用途编辑失败不回滚 | 无 |
| FE-04 | 中 | P2 | 401 过期时多处弹出重复错误；后台标签页仍按 3 秒/5 秒轮询 | 无 |
| FE-05 | 中 | P2 | 长 IP/公钥/接口名溢出；只有一个断点；缺 `:focus-visible`；弹窗不能用 Esc 关闭 | 无 |
| FE-06 | 高 | P2 | 单包 1.5 MB，没有分包 | 低 |
| D-01 | 中 | P1 | Docker：以 root 运行、没有 HEALTHCHECK、`npm install`、缺失目录时构建失败 | **中（卷权限）** |
| D-02 | 中 | P1 | CI 不跑 pytest，Python 依赖没有锁定 | 无 |
| M-01 | 中 | P3 | `main.py` 6394 行、`main.tsx` 7362 行；`on_event` 已弃用；`utcnow()` 已弃用 | 纯重构 |

> 标注“中”风险的几项（B-03、B-08、D-01，以及 S-02 的扩展方案）会触碰存量数据或已部署节点，文中给出了**灰度/兼容方案**，不要一次性直接收紧。

---

## 2. 功能性评估

### 2.1 主流程实测记录

以真实 SQLite 和真实 Agent token 鉴权，通过 TestClient 依次执行（为适配 Windows，`wg` 密钥生成做了替换）：

| # | 流程 | 结果 |
|---|---|---|
| 1 | health / branding / settings 读写 / logo 上传（PNG 魔数校验） | ✅ |
| 2 | Looking Glass Token：创建 → 列表 → 修改 → 轮换 → 吊销 → 删除（明文只在创建/轮换时返回） | ✅ |
| 3 | 创建节点 → `agent/register` → `heartbeat` → 节点状态变为 `online` | ✅ |
| 4 | 受管 GRE：创建 → poll 取到 `gre.apply_config` / `gre.start_interface` → 回报 → 状态从 `changing` 变为 `running` → start/stop/refresh → 删除 | ✅ |
| 5 | 手动 GRE：创建 → 修改 → 删除 | ✅ |
| 6 | 单接口 WireGuard：创建 → 修改 → 写入对端 → plan-apply（diff 中私钥已脱敏）→ confirm → Agent 执行 → 计划状态 `succeeded` | ✅ |
| 7 | 受管 WireGuard 双端：创建（双端 + 互为对端）→ 修改 → 停止 → 删除 | ✅ |
| 8 | 导入扫描 → 上报候选 → 候选列表 → 导入 → 接管 | ✅；**但对已导入配置执行 plan-apply 会生成空 diff，confirm 返回 400**（B-10） |
| 9 | 端口台账：设置范围 → 越界返回 400 → 重复返回 409 → 条目增删改查 | ✅ |
| 10 | 链路监测：创建/修改/样本/删除 + Agent poll/result → 摘要计算正确 | ✅ |
| 11 | 删除节点级联：有连接时返回 409（设计如此）；无连接时台账/任务/设置都清理干净，没有悬挂外键 | ✅ |
| 12 | **异常 1**：删除配置后 Agent 仍拉到 `wireguard.apply_config` | ❌ F-01 |
| 13 | **异常 2**：`DELETE /api/wireguard/configs/{受管单边}` 返回 500 `FOREIGN KEY constraint failed` | ❌ F-02 |
| 14 | **异常 3**：`DELETE /api/wireguard/configs/{受管}/peer` 返回 200，链路变残缺 | ❌ F-03 |

### 2.2 资源 × 操作矩阵（后端 + 前端）

图例：✅ 完整 ⚠️ 有但有缺陷 ❌ 缺失

| 资源 | 增 | 查 | 改 | 删 | 前端入口 | 备注 |
|---|---|---|---|---|---|---|
| 节点 | ✅ | ✅ | ⚠️ 伪 PATCH | ⚠️ 离线对端导致死锁 | ✅ | B-06 / B-09 |
| 节点 Agent Token | ✅ | — | ✅ 轮换 | ❌ 不能单独吊销 | ⚠️ 新建时只 Toast 一次 | FE-01 |
| 拓扑位置 | — | ✅ | ✅ | ✅ 重置 | ✅ | |
| 设置 / Logo | — | ✅ | ⚠️ 不传 `site_title` 会被重置 | ❌ 不能清空 logo | ✅ | B-06 |
| Looking Glass Token | ✅ | ✅ | ✅ | ✅ | ⚠️ **前端没有编辑入口** | FE-02 |
| WireGuard 配置 | ✅ | ✅ | ✅ | ⚠️ 删除后仍下发 / 受管单边 500 | ✅ | F-01 / F-02 |
| 对端 Peer | ✅（PUT） | ✅ | ✅（PUT） | ⚠️ 受管可被误删 | ⚠️ **前端没有删除入口** | F-03 / FE-02 |
| 受管 WireGuard 链路 | ✅ | ✅ | ✅ | ✅ | ✅ | |
| GRE 连接（受管/手动） | ✅ | ✅ | ✅ | ✅ | ✅ | 启停缺去重 B-04 |
| 端口台账范围 | — | ⚠️ GET 有写副作用 | ✅ | ❌ 不能清空 | ✅ | |
| 端口台账条目 | ✅ | ✅ | ✅ | ✅ | ⚠️ 删除无确认 | FE-03 |
| 链路监测 | ✅ | ✅ | ⚠️ 伪 PATCH | ✅ | ⚠️ 删除无确认 | FE-03 |
| 监测样本 | Agent 上报 | ⚠️ 无上限 | — | ⚠️ 只按保留期顺带清理 | ✅ 图表 | P-01 |
| 导入候选 | 扫描生成 | ✅ | — | ❌ | ✅ | |
| 变更计划 | ✅ | ⚠️ 只有详情 | ✅ confirm | ❌ 没有列表/删除 | ✅ | B-10 |
| Agent 任务 | 系统生成 | ✅ | — | ❌ 无清理 | — | P-03 |

**前后端接口对齐**：前端用到的 URL + Method 都能在后端找到（逐条核对，0 处越界）。后端有、前端没用的接口里，真正缺功能的只有两个：`PATCH /api/integrations/looking-glass/tokens/{id}` 和 `DELETE /api/wireguard/configs/{id}/peer`。其余（`/api/protocols`、`/api/node-plugins`、`/api/wireguard/interfaces/*` 兼容别名等）属于冗余或兼容接口。

---

## 3. 功能缺陷（P0，删除相关）

### F-01【高】删除 WireGuard 配置时不取消待执行任务，Agent 会把已删除的配置写回节点

- **位置**：`apps/api/link42_api/main.py:5667-5693` `delete_interface`
- **现象**（已实测）：创建接口 → 写入对端 → plan-apply → confirm → 在 Agent 拉取任务前删除接口（返回 200）→ Agent poll 仍然拿到 `wireguard.apply_config`，里面是完整配置。结果是“删不掉的幽灵接口”。
- **原因**：项目已有 `cancel_pending_interface_tasks()`（`main.py:3481`），但 `delete_interface` 没有调用。接口任务也没有 `deadline_at`，pending 任务永远不会过期。
- **修改**：

```python
@app.delete("/api/wireguard/configs/{interface_id}")
def delete_interface(
    interface_id: int,
    db: Session = Depends(get_db),
    delete_node_config: bool = False,
) -> dict[str, str]:
    """删除 WireGuard 配置；运行中的配置必须先关闭。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    # F-02：受管链路必须走 managed-link 接口整体删除，避免外键错误和半条链路
    if interface.source == "managed-node":
        raise HTTPException(status_code=400, detail="use managed link operation")

    driver = connection_driver_for_interface(interface)

    def cancel_stale_tasks() -> None:
        # F-01：取消尚未被 Agent 拉取的写任务，防止删除后配置被重新下发
        for task_type in (driver.tasks.apply_config, driver.tasks.start, driver.tasks.stop, driver.tasks.status):
            cancel_pending_interface_tasks(db, interface.id, task_type, "interface deleted")

    if interface.source == "imported" and not interface.managed:
        cancel_stale_tasks()
        mark_import_candidate_available_for_interface(db, interface)
        delete_link_monitors_where(db, models.LinkMonitor.interface_id == interface.id)
        db.delete(interface)
        db.commit()
        return {"status": "deleted"}

    require_online_node(db, interface.node_id)
    if interface.runtime_status in ["running", "starting", "stopping"]:
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    cancel_stale_tasks()
    mark_import_candidate_available_for_interface(db, interface)
    if delete_node_config and should_delete_node_config_file(interface):
        enqueue_interface_task_once(db, interface, driver.tasks.delete_config)
    delete_link_monitors_where(db, models.LinkMonitor.interface_id == interface.id)
    db.delete(interface)
    db.commit()
    return {"status": "deleted"}
```

- **兼容性**：只取消 `pending`（Agent 还没拉取）的任务，不影响 `running` 或已完成的任务。`delete_config` 任务是在取消之后才入队的，不会被误取消。
- **注意（待确认）**：`delete_config` 任务的 payload 需要 `interface_id`。接口行删除后，如果 Agent 回报结果时 `agent_task_result` 用 `db.get(WireGuardInterface, id)`，它必须能处理“找不到”的情况。这是原有逻辑就存在的路径，本次修改没有改变它，但建议补一个“删除并清理节点配置 → Agent 回报”的单测来确认。
- 另外，前端对受管链路调用的是 `/managed-link` 接口，所以 F-02 的守卫不会影响现有 UI。

### F-02【高】通用接口删除受管链路单边 → HTTP 500

- **位置**：`main.py:5667`；`models.py:159-164`（`peer_interface_id` 外键没有 ON DELETE）
- **现象**（已实测）：建受管链路 → 停止 → `DELETE /api/wireguard/configs/{local_id}` → `sqlite3.IntegrityError: FOREIGN KEY constraint failed`，返回 500。
- **修改**：见 F-01 代码开头的 `source == "managed-node"` 守卫，把 500 变成明确的 400。

### F-03【高】受管链路的对端可以被单独删除，链路被破坏

- **位置**：`main.py:5532-5540`
- **修改**：

```python
@app.delete("/api/wireguard/configs/{config_id}/peer")
def delete_config_peer(config_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除 WireGuard 点对点配置的唯一对端；受管链路禁止单独删除对端。"""

    config = get_wireguard_config_or_404(config_id, db)
    if config.source == "managed-node":
        raise HTTPException(status_code=400, detail="managed node links must be edited via the managed-link API")
    peer = get_unique_peer(config_id, db)
    if peer is not None:
        db.delete(peer)
        db.commit()
    return {"status": "deleted"}
```

同样的守卫也建议加到 `PUT /api/wireguard/configs/{id}/peer`（`main.py:5514`），防止覆盖受管链路的对端。**要先确认**前端编辑受管链路时不走这个 PUT（审计时看到前端受管链路走的是 `PATCH .../managed-link`，但在 PUT 上加守卫前最好再回归一次）。

---

## 4. 安全问题

### S-01【高】初始管理员密码明文写入日志

- **位置**：`main.py:396-401`
- 密码已经写入 `0600` 权限的 `initial-admin-password` 文件，但又被原样打进 `logger.warning`，会进入 `docker logs` 和日志采集系统。
- **修改**：

```python
logger.warning(
    "Link42 已生成初始管理员凭据 username=%s，一次性密码已写入 %s（权限 0600），修改密码后该文件会自动删除",
    DEFAULT_ADMIN_USERNAME,
    password_path,
)
```

- **兼容性**：README 写的是“首次启动会自动生成登录密码，可在容器日志中查看”，需要同步改成 `docker exec link42 cat /link42/config/initial-admin-password`。如果想保留“看日志就能登录”的体验，可以加开关 `LINK42_PRINT_INITIAL_PASSWORD=1`，默认关闭。

### S-02【高】WireGuard 配置渲染不过滤换行，可注入 `PostUp` 在节点以 root 执行

- **位置**：`packages/link42_wireguard/renderer.py:61-97`；`schemas.py:483-488, 571-577`（`private_key`/`table_name`/`dns`/`endpoint_host` 没有字符校验）
- **实测**：`private_key="AAAA\nPostUp = id > /tmp/pwned"` 渲染出来就是一行独立的 `PostUp`。Agent 端 `system.py:248-279` 把配置原样写盘，再交给 `wg-quick` 以 root 执行。
- **定性**：`custom_config` 本来就允许写 `PostUp`（前端占位符就是这么写的），这是**有意提供的功能**，意味着“面板管理员 = 所有节点的 root”，这点需要在文档里明确。但 **`PrivateKey`、`DNS`、`Table`、`Endpoint` 这些单值字段能注入新行，是缺陷不是功能**：会绕过前端表单的语义，也会让误粘贴的内容把配置文件写坏。
- **修改（第一步，安全、不影响存量）**：渲染层对单值字段拒绝控制字符，`custom_config` 暂时保持原样：

```python
import re

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _safe_value(key: str, value: object) -> str:
    """单值字段不允许包含换行等控制字符，防止注入额外的 wg-quick 指令行。"""
    text = str(value)
    if _CONTROL_CHARS.search(text):
        raise ValueError(f"{key} must not contain newline or control characters")
    return text


def _append(lines: list[str], key: str, value: Optional[object]) -> None:
    """追加单值字段，空值不输出。"""
    if value is None or value == "":
        return
    lines.append(f"{key} = {_safe_value(key, value)}")


def _append_csv(lines: list[str], key: str, values: Optional[object]) -> None:
    """追加逗号分隔字段，兼容字符串和列表输入。"""
    if not values:
        return
    if isinstance(values, str):
        _append(lines, key, values)
        return
    values_list = [_safe_value(key, value) for value in values if value]
    if values_list:
        lines.append(f"{key} = {', '.join(values_list)}")


def _append_raw(lines: list[str], value: Optional[object]) -> None:
    """追加用户自定义 wg-quick 行；禁止重新打开 section，避免把一个 Peer 拆成多个。"""
    if not value:
        return
    for raw_line in str(value).splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.lstrip().startswith("["):
            raise ValueError("custom config must not contain section headers")
        if "\x00" in line:
            raise ValueError("custom config must not contain NUL characters")
        lines.append(line)
```

同时在 API 入口提前拦截，让用户保存时就看到 422，而不是部署时才失败（`schemas.py` 里新增公共校验器，挂到 `InterfaceCreate/InterfaceUpdate/PeerCreate/ManagedLinkCreate/ManagedLinkUpdate` 相应字段上）：

```python
_INLINE_UNSAFE = re.compile(r"[\r\n\x00]")
_WG_KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


def _validate_inline_value(value: str | None) -> str | None:
    if value is None:
        return None
    if _INLINE_UNSAFE.search(value):
        raise ValueError("value must not contain newlines")
    return value.strip()


def _validate_optional_wg_key(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    cleaned = value.strip()
    if not _WG_KEY.fullmatch(cleaned):
        raise ValueError("invalid WireGuard key")
    return cleaned

# 例：InterfaceCreate 内
#   @field_validator("table_name", "fwmark")
#   @classmethod
#   def v_inline(cls, v): return _validate_inline_value(v)
#   @field_validator("dns")
#   @classmethod
#   def v_dns(cls, v): return [_validate_inline_value(x) for x in v]
#   @field_validator("private_key")
#   @classmethod
#   def v_key(cls, v): return _validate_optional_wg_key(v)
#   interface_custom_config: str | None = Field(default=None, max_length=8192)
```

- **兼容性**：
  - 单值字段拒绝换行：正常数据本来就不会有换行，**不会影响现有链路**。
  - `custom_config` 禁止 `[Section]`：如果有用户借 `custom_config` 手工多写了一个 `[Peer]`，会被拒绝。建议**先上线“只告警”版本**：命中时 `logger.warning` 并在 plan diff 里提示，观察一个版本后再改成拒绝。
  - 私钥格式校验会拒绝非标准 key。导入的存量数据不经过 schema，不受影响。
- **第二步（可选，谨慎）**：Agent 端在 `apply_wireguard_config` 前检查 hook 字段，只有 payload 显式带 `allow_hooks=true` 时才放行。**这会影响所有依赖 `PostUp` 的存量连接**，必须先在主控里给已有 hook 的接口补上 `allow_hooks`，再升级 Agent，并且灰度推进。

### S-03【高】udp2raw 二进制下载免鉴权，且下载后不做完整性校验，最终以 root 运行

- **位置**：`apps/agent/link42_agent/middleware.py:548-560` `download_asset`；`main.py:489-490`（免鉴权白名单）、`main.py:5846`
- Agent 自升级有 sha256 校验，udp2raw 却没有，两处标准不一致。主控允许 `http://`，中间人可以替换二进制，拿到节点 root。
- **修改（主控）**：新增 sha256 端点（资产文件是镜像构建时放进去的静态文件，按路径和修改时间缓存哈希即可）：

```python
from functools import lru_cache
import hashlib

@lru_cache(maxsize=64)
def udp2raw_asset_sha256(path_str: str, mtime_ns: int) -> str:
    digest = hashlib.sha256()
    with open(path_str, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.get("/api/agent/plugins/udp2raw/assets/{asset_name}.sha256", response_class=PlainTextResponse)
def get_udp2raw_asset_sha256(asset_name: str) -> str:
    path = resolve_udp2raw_asset_path(asset_name)  # 复用现有下载接口的白名单 + 路径校验逻辑
    stat = path.stat()
    return f"{udp2raw_asset_sha256(str(path), stat.st_mtime_ns)}  {asset_name}\n"
```

> 这个路由必须注册在 `/{asset_name}` 下载路由**之前**，否则会被下载路由先匹配。免鉴权白名单的前缀已经覆盖了这个路径。

- **修改（Agent）**：

```python
def download_asset(config: AgentConfig, asset: str, target: Path, max_bytes: int = 64 * 1024 * 1024) -> None:
    """下载 udp2raw 资产，校验 sha256 后原子替换。"""
    base = f"{config.server_url}/api/agent/plugins/udp2raw/assets/{asset}"
    with request.urlopen(f"{base}.sha256", timeout=30) as response:
        expected = response.read(256).decode("ascii").split()[0].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("invalid udp2raw sha256 response")
    fd, tmp_name = tempfile.mkstemp(prefix="udp2raw-", dir=str(target.parent))
    try:
        digest, total = hashlib.sha256(), 0
        with request.urlopen(base, timeout=60) as response, os.fdopen(fd, "wb") as handle:
            while chunk := response.read(256 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError("udp2raw asset too large")
                digest.update(chunk)
                handle.write(chunk)
        if digest.hexdigest() != expected:
            raise RuntimeError("udp2raw asset sha256 mismatch")
        Path(tmp_name).replace(target)
    finally:
        Path(tmp_name).unlink(missing_ok=True)
```

- **兼容性**：先发布主控（只是新增端点，老 Agent 无感知），再发布 Agent。新 Agent 连到老主控时 `.sha256` 会返回 404，过渡期可以降级：404 时记录告警后继续；下一个版本再改成强制校验。
- **同一信任链上的问题**：自升级和 mimic 都是“同源 sha256”，挡不住发布源本身被篡改。长期方案是 Ed25519 离线签名清单，Agent 内置公钥。另外自升级的 `binary_args` 不应接受 payload 覆盖，应固定为 `["--version"]`（`upgrade.py:129-136`）。

### S-04【中】登录限流的“纯账号维度”可被远程利用，锁死唯一管理员

- **位置**：`main.py:628-670`，限流键为 `[(ip,user), (ip,"*"), ("*",user)]`
- 系统只有一个管理员账号。任何人用错误密码试 5 次就会触发 `("*", 用户名)` 限流，**管理员在 5 分钟窗口内无法登录**，攻击者只要持续尝试就能一直锁住。
- **修改**：抽成函数，去掉纯账号维度；账号维度改为“高阈值、只告警”：

```python
LOGIN_ACCOUNT_ALERT_THRESHOLD = 50


def login_rate_keys(key: tuple[str, str]) -> list[tuple[str, str]]:
    """只按来源、来源+账号限流；纯账号维度只告警不锁定，避免唯一管理员被远程锁死。"""
    return [key, (key[0], "*")]
```

然后把 `login_retry_after` / `record_login_failure` / `clear_login_failures` 中三处硬编码列表替换为 `login_rate_keys(key)`；在 `record_login_failure` 里单独维护 `("*", user)` 计数，超过阈值时 `logger.warning`。
- **兼容性**：只改限流键，不影响登录逻辑。对分布式低频爆破的防护会变弱，但 Argon2id 本身有足够的计算成本，建议同时在反向代理层做 IP 限速。

### S-05【中】Agent 任务失败时把完整 traceback 回传主控

- **位置**：`apps/agent/link42_agent/main.py:456-470`
- 异常字符串可能带上命令参数、文件片段或内部路径，落库后还会通过任务详情接口返回给前端。
- **修改**：

```python
logger.exception("任务执行失败 task_id=%s type=%s", task_id, task_type)  # 完整堆栈只留在节点本地日志
client.report_task(
    task_id,
    "failed",
    {"error": scrub_text_for_log(str(exc))[:2000], "error_type": type(exc).__name__},
)
```

- **兼容性**：前端展示的是 `error` 字段，不受影响。排障时看节点上的 `journalctl -u link42-agent`。

### S-06【中】CORS 放开全部方法和头，并允许凭据

- **位置**：`main.py:180-187`
- **修改**：

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=bool(cors_origins),
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", WEB_CSRF_HEADER],
    max_age=600,
)
```

- **兼容性**：`LINK42_CORS_ALLOWED_ORIGINS` 默认为空，同源部署不受影响。

### S-07【低】其他安全加固

| 项 | 位置 | 建议 |
|---|---|---|
| 用户名用 `!=` 比较 | `main.py:3796` | 改为 `hmac.compare_digest(payload.username.encode(), username.encode())` |
| 免鉴权白名单按前缀匹配（fail-open） | `main.py:473-491` | 改成精确正则，例如 `^/api/agent/releases/[^/]+/(download\|sha256)$`、`^/api/agent/plugins/udp2raw/assets/[A-Za-z0-9_.-]+$`，避免以后在同一前缀下新增的路由被意外放行 |
| 反代终止 TLS 时 HSTS 不生效 | `main.py:972-989` | 可信代理下同时识别 `X-Forwarded-Proto: https`（前提是站点只走 HTTPS，否则不要开启） |
| 全局单会话 | `main.py:236-239` | 新登录会踢掉旧会话，也不能按设备撤销。中长期改为 `web_sessions` 表 |
| Agent 端链路监测目标不做复校验 | `link_monitor.py:14-29` | 用 `ipaddress.ip_address(target_host)` 复校验，防止 `-` 开头的值被 ping 当成选项 |
| udp2raw 包装脚本 `eval "set -- $line"` | `middleware.py:583-595` | 在 `build_udp2raw_args` 中拒绝密码里的 `\r\n\x00`，并限制长度（≤128） |
| 明文 HTTP 传输 Token 和私钥 | `client.py:51-62` | 项目已列为“接受的风险”。建议至少在**非回环地址**使用 `http://` 时打印醒目告警，文档中推荐 HTTPS 反代 |
| env 目录权限 | `deploy/sh/link42-agent.sh:448` | `/etc/link42` 从 `0755` 收紧到 `0700` |
| 下载无大小上限 | `upgrade.py:103-117` | 用 payload 中的 `size` 或固定上限（256 MB）累计计数，超限就中止 |

---

## 5. 并发、幂等与正确性

### B-01【中】Agent 任务领取不是原子操作

- **位置**：`main.py:6070-6098`：先 `SELECT status='pending'`，再在 Python 里改成 `running`。
- Agent 重复拉起（systemd 重启竞态、手工又起一个）或请求重试时，两次 poll 可能拿到同一个任务。`middleware.install`、`agent.self_upgrade` 这类任务被并发执行后果严重。
- **修改**（替换原来的 `for task in tasks: task.status = "running"` 循环）：

```python
from sqlalchemy import update

    if tasks:
        claimed_ids = set(
            db.execute(
                update(models.AgentTask)
                .where(
                    models.AgentTask.id.in_([task.id for task in tasks]),
                    models.AgentTask.node_id == payload.node_id,
                    models.AgentTask.status == "pending",   # 条件更新：只有仍为 pending 才能领取
                )
                .values(status="running", started_at=now)
                .returning(models.AgentTask.id)
                .execution_options(synchronize_session=False)
            ).scalars()
        )
        tasks = [task for task in tasks if task.id in claimed_ids]
        for task in tasks:
            db.refresh(task)
    db.commit()
```

- **兼容性**：`RETURNING` 要求 SQLite ≥ 3.35。`python:3.12-slim`（bookworm）自带 3.40，满足要求。如果要兼容更老的 SQLite，改成逐条 `UPDATE ... WHERE id=? AND status='pending'`，按 `rowcount == 1` 判断。

### B-02【中】变更计划确认不是原子操作，可能重复部署

- **位置**：`main.py:5754-5792`
- **修改**：用条件更新“占领”计划：

```python
    claimed = db.execute(
        update(models.ChangePlan)
        .where(models.ChangePlan.id == plan_id, models.ChangePlan.status == "draft")
        .values(status="confirmed")
        .execution_options(synchronize_session=False)
    ).rowcount
    if not claimed:
        raise HTTPException(status_code=409, detail="change plan is not draft")
    db.refresh(plan)
    # 下面沿用原有逻辑：create_change_plan_agent_tasks(...) / db.commit()
    # 注意：原逻辑中的 “if not plan.diff: 400” 等校验要放在占领之前，否则失败时要回滚为 draft
```

- **兼容性**：返回码不变（重复确认仍是 409）。

### B-03【中】任务结果上报不校验任务当前状态

- **位置**：`main.py:6119-6134`
- Agent 因网络重试重复上报，或对已经超时标记为 `failed` 的任务上报 `succeeded`，都会再次执行副作用（重写 `deployed_config`、改 change plan 状态等）。
- **修改（兼容版）**：

```python
TERMINAL_TASK_STATUSES = {"succeeded", "failed", "cancelled", "expired"}

    if task.status in TERMINAL_TASK_STATUSES:
        logger.warning(
            "忽略终态任务的重复上报 task_id=%s current=%s reported=%s",
            task.id, task.status, reported_status,
        )
        return {"status": "ignored"}
```

- **兼容性（重要）**：有一个场景要特别小心：任务因为 `AGENT_TASK_RUNNING_TIMEOUT` 被主控标记为 failed，但 Agent 最终执行成功了。当前实现会用成功结果覆盖，这在客观上让状态和节点实际情况一致；加了上面的守卫后，这类状态会停留在 failed。**建议**：对 `failed`/`expired` 且原因是超时的任务，仍然接受 `succeeded` 上报（加一个 `task.result.get("reason") == "timeout"` 判断），其余终态忽略。上线前请在测试环境模拟一次超时。

### B-04【中】GRE 启停、中间件安装没有任务去重

- **位置**：`main.py:4436-4488`、`4838-4871`
- WireGuard 走的是 `enqueue_interface_task_once`（有去重），GRE 的 start/stop/refresh 和 `install_node_middleware` 直接建任务，重复点击会产生多条同类任务。
- **修改**：

```python
def endpoint_task_in_flight(db: Session, endpoint_id: int, task_type: str) -> bool:
    return db.scalar(
        select(models.AgentTask.id).where(
            models.AgentTask.type == task_type,
            models.AgentTask.status.in_(["pending", "running"]),
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
        ).limit(1)
    ) is not None

# start_connection / stop_connection / refresh_connection_status 循环内：
#     if not endpoint_task_in_flight(db, endpoint.id, GRE_TASKS.start):
#         create_connection_endpoint_task(db, endpoint, GRE_TASKS.start)
```

- **兼容性**：只减少重复任务，不改变单次行为。

### B-05【中】Looking Glass 节点分页丢数据

- **位置**：`main.py:1113-1153`：先 `LIMIT limit+1`，再在 Python 中按 `online` 过滤，然后用过滤后的条数判断是否还有下一页。被过滤掉的行会让 `next_cursor=None` 提前出现，后面几页的数据就永远拿不到了。
- **修改**：把 online 条件下推到 SQL：

```python
    cutoff = now - timedelta(seconds=settings.agent_offline_after_seconds)
    online_expr = and_(models.Node.status == "online", models.Node.last_seen_at.is_not(None), models.Node.last_seen_at >= cutoff)
    query = select(models.Node).where(models.Node.id > cursor_id).order_by(models.Node.id)
    if region is not None:
        query = query.where(models.Node.region == region)
    if online is True:
        query = query.where(online_expr)
    elif online is False:
        query = query.where(not_(online_expr))
    rows = list(db.scalars(query.limit(limit + 1)))
    page_nodes = rows[:limit]
    next_cursor = str(page_nodes[-1].id) if len(rows) > limit else None
```

- **兼容性**：需要确认 `is_node_online()` 的判断与上面的 `online_expr` 完全一致（阅读代码时两者口径一致；如果以后 `is_node_online` 改了，要同步修改这里）。

### B-06【中】PATCH 接口实际是 PUT 语义

- **位置**：`main.py:4097-4125` + `schemas.py:271-282`（`NodeUpdate`）；`LinkMonitorUpdate`（`schemas.py:703`，继承 Create，`target_host` 必填）；`ControllerSettingsUpdate`（`schemas.py:460`，不传 `site_title` 会重置为 "Link42"）
- **实测**：只传 `name` + `endpoint_ips` 修改节点后，`hostname/management_ip/public_ip` 都被清空。
- **修改（Node）**：

```python
class NodeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    endpoint_ips: list[str] | None = Field(default=None, min_length=1)
    hostname: str | None = Field(default=None, max_length=255)
    region: str | None = Field(default=None, max_length=80)
    management_ip: str | None = None
    public_ip: str | None = None
    topology_endpoint: str | None = Field(default=None, max_length=255)
    github_proxy_url: str | None = Field(default=None, max_length=500)
    # 保留原有 validate_github_proxy_url；新增 management_ip/public_ip 的 IP 校验（见 B-08）
```

```python
@app.patch("/api/nodes/{node_id}", response_model=schemas.NodeRead)
def update_node(node_id: int, payload: schemas.NodeUpdate, db: Session = Depends(get_db)) -> models.Node:
    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    data = payload.model_dump(exclude_unset=True)
    if data.get("name") is not None:
        duplicate = db.scalar(select(models.Node).where(models.Node.name == data["name"], models.Node.id != node_id))
        if duplicate:
            raise HTTPException(status_code=409, detail="node name already exists")
        node.name = data["name"]
    for field in ("hostname", "management_ip", "public_ip", "github_proxy_url"):
        if field in data:
            setattr(node, field, data[field])
    if "region" in data:
        node.region = (data["region"] or "").strip() or None
    if data.get("endpoint_ips") is not None:
        node.endpoint_ips = data["endpoint_ips"]
    if "topology_endpoint" in data or data.get("endpoint_ips") is not None:
        node.topology_endpoint = (data.get("topology_endpoint") or "").strip() or (
            node.endpoint_ips[0] if node.endpoint_ips else None
        )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="node name already exists") from exc
    db.refresh(node)
    return node
```

- **兼容性**：前端 `saveNode`（`main.tsx:3911-3932`）一直提交全量字段，行为不变；只传部分字段的 API 调用方不会再丢数据。`LinkMonitorUpdate`、`ControllerSettingsUpdate` 按同样方式处理（字段改为 Optional，路由使用 `exclude_unset`）。

### B-07【中】SQLite 备份和迁移没有关闭连接（Windows 上会复现失败）

- **位置**：`database.py:141-142`、`153`
- `with sqlite3.connect(...) as conn` 只负责提交/回滚，**不会关闭连接**。Linux 上文件句柄要等 GC 回收；Windows 上 `temporary_path.replace()` 直接报 `WinError 32`（单测 `test_sqlite_upgrade_backup_keeps_single_file` 失败就是这个原因）。
- **修改**：

```python
from contextlib import closing

    with closing(sqlite3.connect(source)) as source_connection, closing(sqlite3.connect(temporary_path)) as backup_connection:
        source_connection.backup(backup_connection)
```

```python
def protect_sqlite_sensitive_values(path: Path) -> int:
    with closing(sqlite3.connect(path)) as connection:
        with connection:          # 保留原来的事务语义
            ...                   # 原逻辑不变
```

- **兼容性**：只是资源管理，没有行为变化。

### B-08【中】输入校验缺口

| 字段 | 位置 | 问题 | 建议 |
|---|---|---|---|
| 接口名 | `schemas.py:479, 568` `max_length=32` | Linux 接口名最长 15 字符，Agent `validation.py:8` 也是 15，结果是“保存成功、部署必失败” | `schemas.py:160` 已经有 `_validate_linux_interface_name`，**只是没被引用**。给 `InterfaceCreate/Update/ManagedLinkCreate` 的名称字段挂上这个校验器 |
| 节点 `management_ip`/`public_ip`/`hostname` | `schemas.py:251-282` | 实测 `public_ip="not-an-ip!!"`、`999.1.2.3`、300 字符的 hostname 都能保存 | 用 `_validate_optional_ip_address`；hostname 加 `max_length=255` |
| `*_custom_config` | `schemas.py:488,524-527,577` | 没有长度上限 | `max_length=8192` |
| Agent 上报的 `hostname/agent_version/capabilities` | `schemas.py:1795-1828` | 没有长度或数量限制 | `hostname ≤255`、`agent_version ≤32`、`capabilities` 最多 64 项且每项 ≤64 |
| import-scan 上报的 `parsed["name"]` | `main.py:6199` | 缺少 `name` 时抛 KeyError，返回 500 | 用 `parsed.get("name")`，不合法的候选直接跳过 |

- **兼容性（重要）**：接口名收紧到 15 字符**只影响新建和修改**，存量的超长名字本来就部署不了。上线前建议执行 `SELECT id,name FROM wg_interfaces WHERE length(name) > 15` 确认存量情况；Update 路由在名称没有变化时跳过校验，避免用户因为历史数据连其他字段都改不了。

### B-09【中】对端长期离线时，连接和节点都删不掉

- **位置**：`delete_connection`（`main.py:4491`）、`delete_managed_link`（`5423`）、`delete_interface`（`5683`）都要求节点在线；`delete_node`（`4783`）只要还有连接就返回 409。
- 对端机器报废后，本端连接和对端节点都无法删除，形成死锁。
- **修改**：删除接口新增查询参数 `force: bool = False`。`force=true` 时跳过在线检查，只清理面板记录（取消 pending 任务，不下发节点侧清理任务）：

```python
def require_online_node_unless_forced(db: Session, node_id: int, force: bool) -> models.Node | None:
    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    if node_runtime_status(node) != "online":
        if not force:
            raise HTTPException(status_code=409, detail="agent is offline; retry with force=true to remove panel records only")
        return None  # 调用方据此跳过节点侧任务
    return node
```

- **兼容性**：默认 False，现有行为不变。前端在收到“离线”409 时弹出二次确认：“对端离线，只删除面板记录，节点上的配置需要手工清理”。

### B-10【低】对仅导入观察的配置执行 plan-apply 会生成无法确认的空计划

- **位置**：`main.py:5571-5600`、`5762`
- **修改**：在 `plan_apply` 开头拦截：

```python
    if interface.source == "imported" and not interface.managed:
        raise HTTPException(status_code=400, detail="imported config is in observe mode; use take-over to manage it")
```

- **兼容性**：需要确认前端对观察态配置是否展示了“生成部署计划”按钮。如果有，要一起隐藏，并补上中文错误映射。

### B-11【低】其他正确性问题

- `create_node` 名称唯一性是“先查后插”，并发时抛 `IntegrityError` 返回 500 → 捕获后返回 409（写法同 B-06）。
- `wg_interfaces` 没有 `(node_id, name)` 唯一约束（`wg_peers` 有）→ 新增唯一索引。**迁移前必须先检查并清理重名数据**，否则建索引会失败并阻塞启动。
- `GET /api/nodes/{id}/port-inventory`（`main.py:4605`）和 `get_unique_peer`（`3363-3378`）在读接口里 `commit()`，GET 请求产生写副作用 → 只在确实新建或清理时提交，或把清理挪到启动迁移。
- `parse_version`（`main.py:1545`，默认 `(0,1,0)`）和 `parse_semver`（`node_plugins/base.py:105`，默认 `(0,0,0)`）逻辑重复、默认值不同 → 统一到 `link42_common`。
- Agent poll 只扫描前 50 条 pending 任务再按能力过滤，前 50 条都不支持时，后面能执行的任务会被饿死 → 扫描上限提高到 200，或把能力过滤下推到 SQL。
- `purge_deleted_looking_glass_tokens`（`database.py:52-74`）启动时会物理删除已吊销的 Token（吊销和旧版软删除的标记相同，无法区分），审计记录丢失 → 增加 `deleted_at` 列来区分，或只清理 `revoked_at` 早于某个版本日期的记录。

---

## 6. 性能

### P-01【高】监测样本全量加载、没有上限

- **位置**：`summarize_monitor`（`main.py:2699-2754`）、`get_link_monitor_samples`（`5227-5254`）
- 按 10 秒一次采样，30 天窗口约 25.9 万行/监测点。摘要和图表接口会把这些行全部读进内存再序列化，节点和链路一多，内存和响应时间都会失控。
- **修改一（摘要改成 SQL 聚合）**：

```python
from sqlalchemy import case, func

def monitor_window_stats(db: Session, monitor_id: int, since: datetime) -> dict:
    S = models.LinkMonitorSample
    total, ok, avg_ms, min_ms, max_ms = db.execute(
        select(
            func.count(S.id),
            func.coalesce(func.sum(case((S.success.is_(True), 1), else_=0)), 0),
            func.avg(S.latency_ms), func.min(S.latency_ms), func.max(S.latency_ms),
        ).where(S.monitor_id == monitor_id, S.checked_at >= since)
    ).one()
    return {"count": total, "success": ok, "avg": avg_ms, "min": min_ms, "max": max_ms}
```

jitter 只需要最近 N 条（例如 300 条）样本：`order_by(S.checked_at.desc()).limit(300)`。

- **修改二（图表接口降采样）**：

```python
MAX_CHART_POINTS = 1000

    total = db.scalar(select(func.count(S.id)).where(S.monitor_id == monitor.id, S.checked_at >= since)) or 0
    step = max(1, math.ceil(total / MAX_CHART_POINTS))
    rows = db.execute(
        select(S.id, S.checked_at, S.success, S.latency_ms)
        .where(S.monitor_id == monitor.id, S.checked_at >= since)
        .order_by(S.checked_at)
    )
    samples = [row for index, row in enumerate(rows) if index % step == 0]   # 流式迭代，不整表 list()
```

更好的做法是按时间桶 `GROUP BY` 求平均值和成功率。同时确认 `link_monitor_samples(monitor_id, checked_at)` 上有复合索引。
- **兼容性**：返回字段结构不变，只是点数变少。7 天、30 天窗口的图表会更“平滑”，需要产品确认可以接受。

### P-02【中】列表接口有 N+1 查询

- **位置**：`interface_read`（`main.py:2768`）、`list_interfaces`（`5061`）、`build_topology`（`3121-3239`）、`list_node_connections`（`4184`）
- **实测**：5 个接口各带 1 个监测时，`GET .../wireguard/configs` 产生 12 条 SQL，`GET .../connections` 产生 15 条。每个接口还要再叠加 P-01 的全量样本加载。
- **修改**：批量预取监测配置，再用一次 `GROUP BY monitor_id` 聚合算出全部摘要：

```python
def monitor_summaries(db: Session, monitor_ids: list[int], since: datetime) -> dict[int, tuple]:
    if not monitor_ids:
        return {}
    S = models.LinkMonitorSample
    rows = db.execute(
        select(S.monitor_id, func.count(S.id),
               func.sum(case((S.success.is_(True), 1), else_=0)),
               func.avg(S.latency_ms))
        .where(S.monitor_id.in_(monitor_ids), S.checked_at >= since)
        .group_by(S.monitor_id)
    ).all()
    return {row[0]: row[1:] for row in rows}
```

给 `interface_read(db, interface, monitor=None, summary=None)` 增加可选参数，列表接口传入预取结果，单条读取保持原样。响应结构不变。

### P-03【中】任务和查询记录无限增长；入队时重复扫描

- `AgentTask`、`LookingGlassQuery` 没有清理机制 → 在 startup 和定时任务中清理（或在 `agent_poll` 里按 60 秒节流执行）：

```python
TASK_RETENTION_DAYS = 30

def purge_old_records(db: Session, now: datetime) -> None:
    db.execute(delete(models.AgentTask).where(
        models.AgentTask.status.in_(["succeeded", "failed", "cancelled", "expired"]),
        models.AgentTask.finished_at < now - timedelta(days=TASK_RETENTION_DAYS),
    ))
    db.execute(delete(models.LookingGlassQuery).where(models.LookingGlassQuery.expires_at < now))
```

  **注意**：如果 `ChangePlan` 等表通过外键引用了任务 id，删除前要确认约束（或只清理没有被引用的任务）。
- `enqueue_interface_task_once_with_task`（`main.py:3448`）每次入队都调用 `expire_stale_running_agent_tasks` → 改成模块级按单调时钟每 30 秒最多执行一次，并补上索引 `CREATE INDEX IF NOT EXISTS ix_agent_tasks_status_started ON agent_tasks(status, started_at)`。
- 同步路由里的 `wg genkey` 子进程和 Argon2 计算会占用线程池（默认 40 个线程）。可以用 `cryptography` 的 X25519 在进程内生成密钥（需要 clamp 后 base64，保留 `wg` 作为回退），创建一条受管链路可以少起 3 个子进程。

---

## 7. 前端

前端的安全基线不错：会话走 HttpOnly + SameSite=Strict Cookie，`localStorage` 只存主题；所有写请求都带 `X-Link42-CSRF`；没有 `dangerouslySetInnerHTML`、没有 `any`、没有 `console.*`。下面是需要处理的问题。

### FE-01【高】新建节点的 Agent 令牌只在 3.8 秒的 Toast 里出现一次

- **位置**：`apps/web/src/main.tsx:3893-3901`；`notify` 在 `2606-2613`，成功消息 3800 ms 后自动消失
- 令牌只有创建时返回一次，主控不保存明文。用户稍一走神就只能去“轮换令牌”。安装命令很长，在 Toast 里也没法方便地复制。
- **修改**：用持久弹窗展示，带复制按钮：

```tsx
// state
const [createdNode, setCreatedNode] = useState<{ node: NodeItem; token: string; controllerUrl: string } | null>(null);

// createNode 成功后，替换原来的 notify(...)
setCreatedNode({ node: result.node, token: result.agent_token, controllerUrl });
notify("success", `节点 ${result.node.name} 已创建，请保存 Agent 安装命令。`);

// JSX（复用现有 modalBackdrop / modalPanel 样式）
{createdNode && (
  <div className="modalBackdrop" role="dialog" aria-modal="true">
    <section className="modalPanel">
      <h2>节点已创建</h2>
      <p className="hint">Agent 令牌只显示这一次，关闭后只能通过“轮换令牌”重新获取。</p>
      <pre className="tokenBox">{buildAgentCommand(createdNode.node, createdNode.token, createdNode.controllerUrl)}</pre>
      <div className="actions">
        <button type="button" onClick={() => void navigator.clipboard.writeText(
          buildAgentCommand(createdNode.node, createdNode.token, createdNode.controllerUrl),
        ).then(() => notify("success", "已复制安装命令"))}>复制安装命令</button>
        <button type="button" className="secondary" onClick={() => setCreatedNode(null)}>我已保存</button>
      </div>
    </section>
  </div>
)}
```

- **兼容性**：只是新增弹窗。`navigator.clipboard` 需要 HTTPS 或 localhost，HTTP 内网部署时要回退到 `document.execCommand("copy")`，项目里现有的复制函数可以直接复用。

### FE-02【中】两个功能入口缺失

1. **删除对端**：后端有 `DELETE /api/wireguard/configs/{id}/peer`，前端没有入口。

```tsx
async function deletePeer() {
  if (!selectedConfigId) return;
  if (!window.confirm("确定删除当前配置的对端？删除后需要重新生成部署计划。")) return;
  await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}/peer`, { method: "DELETE" });
  await refreshPeer(selectedConfigId);
  notify("success", "对端已删除，请重新生成部署计划。");
}
// 只对非受管配置显示按钮（配合后端 F-03 守卫）
{peer && selectedConfig?.source !== "managed-node" && (
  <button className="danger" type="button" onClick={() => void runAction(deletePeer, `peer-delete-${selectedConfig.id}`)}>删除对端</button>
)}
```

2. **编辑 Looking Glass Token**：后端有 `PATCH /api/integrations/looking-glass/tokens/{id}`（改名、scopes、启停、过期时间），前端只能轮换、吊销、删除。

```tsx
async function updateLookingGlassToken(id: number, patch: { name?: string; enabled?: boolean; scopes?: string[]; expires_at?: string | null }) {
  await api(`/api/integrations/looking-glass/tokens/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
  await refreshLookingGlassTokens();
  notify("success", "Token 已更新。");
}
```

在 Token 行的操作区增加“启用/停用”开关和“编辑”按钮即可。

### FE-03【中】删除没有二次确认；乐观更新失败不回滚

- `deleteLinkMonitor`（`main.tsx:3547`）和 `deletePortInventoryEntry`（`3282`）直接发 DELETE。节点、配置、GRE、Token 都有 `window.confirm`，这两处不一致：

```ts
if (!window.confirm("确定删除该链路监测？历史样本会一并清理。")) return;
if (!window.confirm(`确定删除端口 ${entry.port}/${entry.protocol} 的台账记录？`)) return;
```

- 端口用途编辑（`5273-5284` onChange 先改本地状态，`3269` 失焦时保存）失败后本地值不回滚，用户会以为已经保存：

```ts
async function updatePortInventoryEntryPurpose(entry: PortInventoryEntry, purpose: string) {
  if (!selectedNodeId) return;
  try {
    const updated = await api<PortInventoryEntry>(
      `/api/nodes/${selectedNodeId}/port-inventory/entries/${entry.id}`,
      { method: "PATCH", body: JSON.stringify({ purpose }) },
    );
    setPortInventory((cur) => cur ? { ...cur, entries: cur.entries.map((e) => e.id === updated.id ? updated : e) } : cur);
  } catch (error) {
    await refreshPortInventory(selectedNodeId);   // 失败时回到服务端真值
    throw error;
  }
}
```

- `deleteEditingNode`（`3945-3950`）用当前**选中**节点的 `configs.length` 来预检查**正在编辑**的节点，两者可能不是同一个节点。后端已经返回 409 并有中文映射，建议直接删掉这段前端预检查。

### FE-04【中】轮询、会话过期、竞态

- **会话过期时重复报错**：`api()` 在 401 时派发 `AUTH_EXPIRED_EVENT`，但十几处 `useEffect` 里写的是 `.catch((e) => notify("error", formatUserError(e)))`（如 `3604/3629/3661/3693/3766/3820`），跳回登录页的同时还会弹出错误 Toast。统一处理：

```ts
function notifyApiError(error: unknown) {
  if (error instanceof Error && error.message.startsWith("401:")) return; // 已由 auth-expired 统一处理
  notify("error", formatUserError(error));
}
```

- **后台标签页仍在轮询**：5 秒全量刷新（`3601-3611`）加上选中配置的 3 秒刷新（`3828-3854`），平均约 1.8 秒一个请求。在定时器回调开头加 `if (document.hidden) return;`；3 秒轮询只在配置处于 starting/stopping/changing 状态时开启。
- **定时器不清理**：`notify` 和 `scheduleGreConnectionRefresh`（`3024-3031`）里的 `setTimeout` 在组件卸载时不会清理。用 `useRef<number[]>` 统一登记，在卸载的 cleanup 里 `clearTimeout`。
- **`runAction` 防重复提交读的是闭包里的旧 Set**（`2753-2762`）：快速双击或 Ctrl+S（BIRD 编辑器 `3457`）可能提交两次。改成用 `useRef<Set<string>>` 作为判断依据，state 只用于渲染 disabled。
- **`useEffect` 依赖不完整**：例如 `3643-3649` 依赖 `[editingNodeId]` 却读取 `editingNode`，保存节点后入口地址列表不会刷新 → 改为 `[editingNode]`。项目没有 ESLint，建议加上 `react-hooks/exhaustive-deps`（见 FE-07）。

### FE-05【中】样式与可访问性

| 问题 | 位置 | 修改 |
|---|---|---|
| 长 IP 列表、公钥（44 字符）、长接口名在窄屏撑破卡片 | `styles.css:1498-1501`（`.nodeHeader small, .configRow small`）、`1876-1883`（`.peer`）、`1655-1659`（`.protocolCard small`） | 见下方 CSS 片段 1 |
| 只有一个 760px 断点，761–1024px 平板区间里 `.portInventoryEntryForm`（4 列）、`.monitorStats`（5 列）很挤 | `styles.css:2169` | 见下方 CSS 片段 2 |
| 输入框 `outline:none`，按钮没有 `:focus-visible`，键盘用户看不到焦点 | `styles.css:151-157` | 见下方 CSS 片段 3 |
| 没有 `prefers-reduced-motion` | `styles.css:2300-2336` 动画 | 见下方 CSS 片段 3 |
| 拓扑画布 `touch-action:none`，在移动端这个区域无法滚动页面 | `styles.css:394` | 移动端改成 `pan-y`（**需要真机验证是否影响拖拽节点**） |
| 监测摘要小字 `opacity:0.76` 叠在浅色背景上，对比度不足 | `styles.css:1747-1751` | `opacity:1`，改用颜色控制层级 |
| 死选择器 `.nodeCreateForm`、`.row/.row.active/.row small` | `styles.css:607-611, 1678-1693` | 删除 |
| 弹窗不能用 Esc 关闭，没有初始焦点，关闭后焦点不回到触发按钮 | 各 `modalBackdrop` | 用统一的 `useEffect` 监听 keydown Escape，按弹窗层级依次关闭 |
| 新增插件时插件弹窗会出现空白标签页（只渲染了 bird/port-inventory） | `main.tsx:5001-5013, 5024, 5163` | 未知插件显示“该插件暂无界面”兜底 |

```css
/* 片段 1：长文本换行 */
.nodeHeader small,
.configRow small,
.peer span,
.protocolCard small {
  min-width: 0;
  overflow-wrap: anywhere;
}

/* 片段 2：平板断点 */
@media (max-width: 1024px) {
  .portInventoryEntryForm { grid-template-columns: 1fr 1fr; }
  .monitorStats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
  .topologyCanvas { touch-action: pan-y; }
}

/* 片段 3：焦点可见与减少动画 */
button:focus-visible,
a:focus-visible,
[role="button"]:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    transition-duration: 0.001ms !important;
  }
}
```

> 说明：样式问题是根据 CSS 源码和组件结构推断的，没有在真实浏览器里逐页截图验证。改完后建议在 375px、768px、1440px 三个宽度下各过一遍主要页面。

### FE-06【高】单包 1.5 MB，登录页也要加载 CodeMirror、recharts、xyflow

- **位置**：`apps/web/vite.config.ts`（没有分包配置）
- **修改一（改动最小）**：Vite 8 用 Rolldown，`manualChunks` 的对象写法可能不支持，**用函数写法**：

```ts
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("@codemirror") || id.includes("@uiw") || id.includes("@lezer")) return "editor";
          if (id.includes("recharts") || id.includes("d3-")) return "charts";
          if (id.includes("@xyflow")) return "flow";
          if (id.includes("react-select") || id.includes("react-arborist")) return "select";
          if (id.includes("react-dom") || id.includes("/react/") || id.includes("scheduler")) return "react";
          return "vendor";
        },
      },
    },
  },
  // server / preview 配置保持原样
});
```

- **修改二（效果更好）**：把 BIRD 编辑器、监测图表、拓扑画布拆成独立组件，用 `React.lazy` + `<Suspense>` 按需加载。这需要配合 FE-07 的文件拆分。
- **兼容性**：只影响构建产物。改完后跑 `npm run build`，确认没有循环 chunk 警告，再用 `vite preview` 冒烟一次。

### FE-07【中】工程化

- **`main.tsx` 有 7362 行**，一个 `App` 组件里有 40 多个 handler、30 多个 state。建议按下面的顺序拆分，先拆没有依赖的部分：`api/client.ts`（`api` 和错误翻译）→ `types.ts` → `components/forms/*` → `TopologyCanvas`、`BirdEditor`、`MonitorModal`、`PortInventoryPanel`、`SettingsModal` → `hooks/usePolling`、`useToasts`、`usePendingActions`。每拆一步都跑一次 `tsc` 和 `vitest`。
- **加 ESLint**：

```bash
npm i -D eslint @eslint/js typescript-eslint eslint-plugin-react-hooks globals
```

```js
// eslint.config.js
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { plugins: { "react-hooks": reactHooks }, rules: { ...reactHooks.configs.recommended.rules } },
);
```

  `package.json` 加 `"lint": "eslint src"`。第一次运行会报出一批 `exhaustive-deps`，建议先设为 warn，再分批修复。**不要一次性按提示全部加依赖**，有些 effect 加依赖后会变成无限循环。
- **recharts 2.x** 已提示 `1.x and 2.x branches are no longer active`（npm install 时实测看到）。先把版本锁在 `~2.15.4`，等图表组件拆出来以后再升级到 3.x 并回归图表。
- 小问题：`INFERRED_API_BASE` 恒为空串（`main.tsx:460-467`）；错误翻译表里有“中文→同一句中文”的无效映射（`768-770`）；后端返回的 `CSRF validation failed` 没有中文映射。

---

## 8. Agent、部署与 CI

### D-01【中】Docker 镜像

| 问题 | 位置 | 说明 |
|---|---|---|
| `npm install` 而不是 `npm ci` | `Dockerfile.controller:5` | 不能保证严格按 lock 文件安装，依赖可能漂移 |
| 以 root 运行 uvicorn | 整个 runtime 阶段没有 `USER` | |
| 没有 HEALTHCHECK | — | `/api/health` 也不检查数据库 |
| 基础镜像没有固定 digest | `:1`、`:14` | |
| `COPY dist/controller-agent-releases` | `:28` | 干净 clone 后没有这个目录，`docker compose build` 会直接失败 |
| runtime 安装了 `wireguard-tools` | `:19-21` | 主控用 `wg genkey` 生成密钥，**确实需要**（除非按 P-03 改成 X25519），不要删 |

**修改（兼容已有 root 属主的数据卷）**：

```dockerfile
FROM node:20-bookworm-slim AS web-build
WORKDIR /src/apps/web
COPY apps/web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
# ...（ENV、apt 安装 wireguard-tools 保持原样）
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /opt/link42 link42
# ...（COPY 源码 / pip install 保持原样）
COPY deploy/docker-entrypoint.sh /usr/local/bin/link42-entrypoint
RUN chmod 0755 /usr/local/bin/link42-entrypoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status == 200 else 1)"
ENTRYPOINT ["/usr/local/bin/link42-entrypoint"]
CMD ["uvicorn", "link42_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
```

```sh
#!/bin/sh
# deploy/docker-entrypoint.sh：以 root 启动，修正卷权限后降权运行；设置 LINK42_RUN_AS_ROOT=1 可保持旧行为
set -eu
mkdir -p /link42/data /link42/config
if [ "$(id -u)" = "0" ] && [ "${LINK42_RUN_AS_ROOT:-0}" != "1" ]; then
  chown -R link42:link42 /link42
  exec gosu link42 "$@"
fi
exec "$@"
```

发布资产目录缺失的问题：在 `build-image.sh` 开头加检查，并在 README 中说明 `docker compose build` 前要先执行 `scripts/agent/prepare-release-assets.sh`。或者在 Dockerfile 里改成 `COPY dist/controller-agent-release[s] ./releases/agent`（通配写法在目录不存在时不会报错，需要在当前 BuildKit 版本上实测）。

**兼容性（重要）**：
- 老用户的 `/opt/link42` 属主是 root。entrypoint 首次启动时执行一次 `chown`，用户无感知。
- 如果用户把 `/link42` 挂载成只读或 NFS（root_squash），`chown` 会失败 → 可以设置 `LINK42_RUN_AS_ROOT=1` 回退。
- `master.key` 必须能被 `link42` 用户读取，`chown -R` 已经覆盖。
- `/api/health` 建议同时执行一次 `SELECT 1`，这样 HEALTHCHECK 才能反映数据库是否可用。

### D-02【中】CI 与依赖

- `.github/workflows/security.yml` 只做明文凭据扫描和 `npm audit`，**没有跑 pytest、vitest、tsc**。建议新增：

```yaml
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e ".[dev]" && python -m pytest -q
      - uses: actions/setup-node@v4
        with: { node-version: "22", cache: npm, cache-dependency-path: apps/web/package-lock.json }
      - run: npm ci --prefix apps/web && npm test --prefix apps/web && npm run build --prefix apps/web
```

- `pyproject.toml` 的依赖全部是 `>=`，没有锁文件。镜像每次构建都可能拿到新的大版本（例如 Starlette 已经开始提示 `httpx` → `httpx2` 的弃用警告）。建议用 `uv lock` 或 `pip-compile` 生成锁文件，Dockerfile 按锁文件安装；至少给 FastAPI、Starlette、SQLAlchemy、Pydantic 加上上限（`<下一个大版本`）。
- 可选：加 `pip-audit` 和 `bandit -r apps packages`。

### D-03【低】systemd、安装脚本与 Agent 可靠性

- `deploy/systemd/link42-agent.service`：Agent 需要 root，但可以先加上**不影响功能**的加固项：`NoNewPrivileges=yes`、`PrivateTmp=yes`、`ProtectHome=yes`、`RestrictSUIDSGID=yes`。**不要**加 `ProtectSystem=strict` 或收紧 `CapabilityBoundingSet`，否则会破坏写 `/etc/wireguard`、`systemctl`、`dpkg -i`（mimic）这些操作。安装脚本 `deploy/sh/link42-agent.sh:470-489` 生成的 unit 要同步修改。
- `link42-api.service` 可以使用独立用户，并加上 `ProtectSystem=strict` + `ReadWritePaths=/opt/link42`。
- Agent 主循环（`agent main.py:516-547`）断线后固定每 2 秒重试 → 改成指数退避加抖动：

```python
failures = 0
while True:
    try:
        run_once(config)
        failures = 0
        time.sleep(config.poll_interval)
    except Exception:
        failures += 1
        delay = min(60.0, config.poll_interval * (2 ** min(failures, 5)))
        logger.exception("轮询失败，%.1f 秒后重试", delay)
        time.sleep(delay * random.uniform(0.8, 1.2))
```

- 导入的 wg-quick 配置里如果有 `PreUp/PostUp` 钩子，会被原样保存并在接管后重新下发（`parser.py:180-187`）。建议导入时写入 `warnings`，并在接管计划页醒目提示“该配置包含会在节点上以 root 执行的命令”。
- Agent 端已经核实**实现正确**的部分：接口名白名单和符号链接逃逸防护（`validation.py`）、私钥文件 `0600` 权限和原子写入、所有 `subprocess` 调用都用参数数组（没有 `shell=True`）、Looking Glass 参数校验和输出截断、安装脚本强制校验 sha256。

---

## 9. 可维护性

| 项 | 建议 |
|---|---|
| `main.py` 有 6394 行，混合了路由、鉴权、任务编排、状态机、拓扑、Looking Glass | 拆成 `routers/{auth,nodes,wireguard,gre,monitors,port_inventory,looking_glass,agent}.py` 和 `services/{tasks,topology,monitor}.py`，`main.py` 只负责组装。纯搬迁，以现有 267 个通过的测试作为回归基线 |
| `@app.on_event("startup")` 已弃用（运行 pytest 时有告警） | 改用 `lifespan`：`app = FastAPI(..., lifespan=lifespan)`，启动逻辑原样搬进去 |
| 30 多处 `datetime.utcnow()`（Python 3.12 已弃用） | 封装 `utcnow_naive() = datetime.now(timezone.utc).replace(tzinfo=None)` 后一次性替换。**不要改成带时区的 datetime**，数据库列是 naive，混用会导致比较出错 |
| 重复代码：`require_udp2raw_ip`/`require_mimic_ip`、两个 `upsert_*_link_monitor`、`parse_version`/`parse_semver` | 合并成公共函数 |
| 任务 payload 用 JSON 路径查询 `payload["interface_id"].as_integer()` | 把常用于查询的 `interface_id`、`connection_endpoint_id` 提升为独立列并建索引。需要迁移和回填，建议和 B-04 一起做 |

---

## 10. 修改路线建议

按“风险低、收益高”的顺序分三批推进，每批都跑一遍完整回归（pytest、vitest、§2.1 的 14 步流程）。

**第一批（上线前，均为局部改动，不改变现有流程）**
S-01、S-02（第一步：单值字段拒绝控制字符）、F-01、F-02、F-03、B-01、B-02、B-07、S-05、S-06、FE-01、FE-03

**第二批（下一个版本）**
S-03（先发主控，再发 Agent，过渡期允许降级）、S-04、B-03（带超时豁免）、B-04、B-05、B-06、B-08（先查存量数据）、B-09、P-01、P-02、P-03、FE-02、FE-04、FE-05、FE-06、D-01（带 `LINK42_RUN_AS_ROOT` 回退）、D-02

**第三批（中长期）**
S-02 第二步（Agent 端 hook 策略，需要灰度）、自升级/mimic 签名链、Web 会话表、`main.py`/`main.tsx` 拆分、`lifespan`/`utcnow` 迁移、任务查询列提升、recharts 3 升级

### 需要谨慎、可能影响现有流程的改动

| 改动 | 可能影响 | 建议做法 |
|---|---|---|
| S-02 `custom_config` 禁止 `[Section]` | 手工多写 Peer 的用户 | 先告警一个版本，再拒绝 |
| S-02 第二步 Agent 拒绝 hook | 所有使用 PostUp 的存量连接 | 主控先给存量接口补 `allow_hooks`，再灰度升级 Agent |
| S-03 强制校验 udp2raw sha256 | 新 Agent 连老主控时安装失败 | 过渡期 404 时降级并告警 |
| B-03 终态任务忽略上报 | 超时后才成功的任务状态停在 failed | 对超时导致的 failed 仍接受 succeeded |
| B-08 接口名 ≤15、节点 IP 校验 | 带历史脏数据的记录无法编辑 | 名称没有变化时跳过校验；先跑 SQL 查看存量 |
| B-11 `wg_interfaces` 唯一索引 | 存量有重名数据时启动失败 | 迁移前先检测，有重名就只告警不建索引 |
| D-01 非 root 运行 | 只读卷、NFS root_squash | 提供 `LINK42_RUN_AS_ROOT=1` 回退 |
| S-01 不再把密码写进日志 | README 中“看日志获取密码”的说明 | 同步更新文档，可选开关保留旧行为 |
| P-01 图表降采样 | 长窗口图表细节变少 | 产品确认点数上限 |

---

## 附录 A：Windows 下失败的 9 个单测

| 用例 | 原因 | 是否代码问题 |
|---|---|---|
| `test_bird_validate_restores_original_file_metadata` | `os.chown` 在 Windows 上不存在 | 否（Agent 只运行在 Linux） |
| `test_mimic_layout_and_system_config_permissions` | Windows 上 chmod 结果是 0o777 | 否 |
| `test_stop_interface_waits_for_openwrt_netifd` / `test_apply_config_uses_openwrt_uci_backend` / `test_openwrt_backend_is_reported_as_agent_capability` | 探测不到 UCI/systemd 后端 | 否 |
| `test_agent_platform_reports_musl_libc` | 平台探测 | 否 |
| `test_self_upgrade_rejects_foreign_download_url` | 没有 systemd/procd | 否 |
| `test_openwrt_upgrade_script_contains_rollback` | `Path` 在 Windows 上生成了反斜杠路径 | 否（但生成 shell 脚本时建议用 `PurePosixPath`，更稳妥） |
| `test_sqlite_upgrade_backup_keeps_single_file` | `WinError 32`：连接未关闭 | **是**，见 B-07 |

## 附录 B：已核实做得好的地方

- 密码用 Argon2id；Agent/API token 只存哈希，比较时用 `compare_digest`
- WireGuard 私钥、PSK、任务敏感 payload 用 AES-GCM 字段级加密，`master.key` 单独存放
- Cookie 设置 HttpOnly + SameSite=Strict，写请求要求自定义 CSRF 头，有 CSP 和请求体大小限制
- 删除默认只删除面板记录，节点清理需要显式勾选；升级前自动备份数据库
- Agent 接口名白名单、防符号链接逃逸、配置原子写入、私钥文件 0600
- 变更先生成 plan 和 diff（私钥已脱敏），确认后才下发
- 测试覆盖面大（276 个 Python 用例 + 20 个前端用例）


---

## 12. 整改闭环 Checklist（2026-10-01）

以下清单按本报告的全部编号逐项核对。状态中的“风险接受”表示已经结合现有部署兼容性和产品要求保留，并不是遗漏；证据以当前工作区代码和测试为准。

| 编号 | 状态 | 代码/测试证据 | 兼容性说明 |
|---|---|---|---|
| S-01 | 风险接受，已加固 | `apps/api/link42_api/config.py` 的 `print_initial_password`；`main.py` 同时写入权限 `0600` 的 `initial-admin-password`，支持关闭日志明文 | 按部署兼容要求默认继续输出初始密码；生产可设置 `LINK42_PRINT_INITIAL_PASSWORD=false` |
| S-02 | 已修复第一阶段 | `packages/link42_wireguard/renderer.py` 单值字段控制字符拦截；`apps/api/link42_api/schemas.py` 统一校验器；安全回归测试 | `custom_config`/hooks 保持兼容，仍明确属于管理员可执行 root 命令能力 |
| S-03 | 已修复，保留旧主控兼容 | `main.py` 中间层资产白名单、Agent token 鉴权、`.sha256` 路由；`middleware.py:download_asset` 原子下载、大小限制和 SHA256 校验；`test_middleware_assets_require_agent_token_and_verify_checksum` | 新 Agent 连接旧主控时 404 可降级并记录告警 |
| S-04 | 已修复 | `login_rate_keys` 仅按来源和来源+账号限流，去除可锁死唯一管理员的全局账号锁定 | 仍由来源限流、Argon2 和反向代理层共同承担爆破防护 |
| S-05 | 已修复 | Agent 失败结果只回传摘要，完整堆栈留节点日志；任务结果回归测试 | 前端仍读取 `error` 字段，API 结构兼容 |
| S-06 | 已修复 | `main.py` CORS 仅开放明确方法和 `Authorization`、`Content-Type`、CSRF 头 | 默认空 CORS 与同源部署不变 |
| S-07 | 已修复可操作项，部分风险接受 | 用户名常量时间比较、精确免鉴权路径、可信反代来源/HSTS、监测目标 IP 复校验、中间层参数限制、自升级大小限制均已实现 | 单会话踢旧会话、HTTP 主控兼容按产品/部署要求保留 |
| F-01 | 已修复 | `delete_interface`、`delete_managed_link` 取消 pending 任务；`test_force_delete_offline_wireguard_cleans_tasks_and_monitor` | running 任务不假装撤销；force 明确表示节点侧需人工清理 |
| F-02 | 已修复 | 受管接口删除入口返回明确 400，必须使用 managed-link API；受管删除回归测试 | 不再触发外键 500 |
| F-03 | 已修复 | `set_unique_peer`、`put_config_peer`、`delete_config_peer` 拒绝 `source=managed-node` | 受管连接继续通过专用 managed-link API 编辑 |
| B-01 | 已修复并测试 | `agent_poll` 条件更新 `status=pending` 逐条领取；`test_agent_poll_second_request_cannot_reclaim_running_task` | 不依赖 SQLite `RETURNING`，兼容旧环境 |
| B-02 | 已修复并测试 | `confirm_change_plan` 条件更新 draft→confirmed；接口改名计划测试包含重复确认 409 | 重复确认 API 行为保持 409 |
| B-03 | 已修复并测试 | `agent_task_result` 忽略普通终态重复回报，超时失败允许最终 succeeded；对应专项测试 | 兼容旧 Agent 重试和超时后实际成功 |
| B-04 | 已修复并测试 | `endpoint_task_in_flight`/`enqueue_connection_endpoint_task_once`、中间层安装任务去重；GRE 与 `test_mimic_install_task_uses_github_latest_and_node_proxy` 重复调用测试 | 只合并 pending/running 同类任务；加密 payload 的 `plugin` 字段在解密后比较 |
| B-05 | 已修复并测试 | Looking Glass `online` 条件下推 SQL；`test_looking_glass_online_pagination_filters_before_limit` | 游标和响应字段不变 |
| B-06 | 已修复并测试 | Node/Settings/LinkMonitor 使用 `exclude_unset`；`test_partial_updates_preserve_unmentioned_fields` | 前端全量提交继续兼容，部分 PATCH 不再清空字段 |
| B-07 | 已修复并测试 | `database.py` 使用 `closing(sqlite3.connect(...))`；`test_sqlite_upgrade_backup_keeps_single_file` | 仍只保留一个固定升级备份 |
| B-08 | 已修复并测试 | 接口名最长 15、节点 IP/hostname、自定义配置、Agent 上报字段和导入候选均有校验 | 存量超长名称不因修改其它字段被阻断 |
| B-09 | 已修复并测试 | `force=true` 支持离线 WireGuard、GRE、受管连接和节点清理；四个 force 删除专项测试覆盖任务、外键、监测、查询 | 默认删除行为不变；force 不向离线节点下发清理 |
| B-10 | 已修复 | `plan_apply` 拒绝未接管 imported observe 配置；接管流程单测 | 观察态配置继续可读，必须显式 take-over |
| B-11 | 已修复 | 节点唯一性 IntegrityError→409、SQLite 对端/接口约束迁移、GET 端口台账不再 commit、版本解析统一 | 迁移先清理历史重复对端，不自动破坏性改名 |
| P-01 | 已修复并测试 | 摘要 SQL 聚合、jitter 上限样本、图表响应 `MONITOR_RESPONSE_MAX_SAMPLES`；监测上限专项测试 | 响应结构不变，长窗口点数固定 |
| P-02 | 已修复并测试 | `summarize_monitors` 批量聚合，列表/拓扑预取摘要；专项测试比较批量和单条结果 | 单详情读取行为不变 |
| P-03 | 已修复并测试 | 启动和 Agent poll 节流清理样本、过期查询和终态任务；保留期专项测试 | 保留 ChangePlan 关联任务，避免部署历史失效 |
| FE-01 | 已修复 | 创建节点后使用持久凭据弹窗，Token/安装命令均可复制；前端构建通过 | 明文只在创建/轮换响应和当前弹窗显示，主控不落库 |
| FE-02 | 已修复 | 设置页提供 Looking Glass Token 编辑/轮换/吊销/删除；普通 Peer 提供入口，受管 Peer 由后端保护 | 不影响 Looking Glass 第三方 API；Token 删除为物理删除 |
| FE-03 | 已修复 | 监测、端口台账删除增加确认；端口用途保存失败刷新回滚 | 只增加交互确认 |
| FE-04 | 已修复 | `pendingActionsRef` 防重复请求；后台隐藏时暂停轮询；统一会话错误处理 | 可见页面轮询和单会话策略保持兼容 |
| FE-05 | 已修复 | `styles.css` 长文本换行、平板断点、`:focus-visible`、移动拓扑触摸、Escape 关闭弹窗 | 仅增加响应式和可访问性规则 |
| FE-06 | 已修复 | `vite.config.ts` 将 React、编辑器、图表、拓扑和选择器分包；构建无单个超大 chunk 警告 | `recharts` 锁定在 2.x 兼容范围 |
| FE-07 | 部分完成，风险接受 | CI 已加入 Vitest、pytest、compileall、build；当前保留大文件结构，未做高风险组件搬迁 | 组件拆分和 ESLint 作为后续纯重构，避免改变大量交互状态依赖 |
| D-01 | 已按部署要求整改并实机验证 | Docker 使用 `npm ci`、健康检查、`dist/controller-agent-releases/.gitkeep`；保持 root 运行；临时容器验证 `/api/health` 返回 200、UID 0、引导文件权限 0600 | 按部署兼容要求不改为非 root；卷权限和初始密码日志行为保持可用 |
| D-02 | 已修复并测试 | CI 执行 Python/前端测试、compileall、build；`pyproject.toml` 增加主要依赖上限；lock 文件同步 | 依赖仍允许同一大版本内补丁更新 |
| D-03 | 已修复并测试 | Agent systemd unit/安装脚本加入安全项；主循环指数退避；安装、自升级和服务脚本回归测试 | 未收紧会破坏 WireGuard、OpenWrt、systemd、mimic 的权限能力 |
| M-01 | 已完成低风险项，长期风险接受 | FastAPI lifespan、`utcnow` 封装、版本解析公共函数、日志和任务清理已完成；全量测试/编译通过 | `main.py`/`main.tsx` 大模块拆分属于后续纯搬迁 |

### 12.1 本轮验证命令

```text
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q apps/api apps/agent packages
git diff --check
npm test --prefix apps/web -- --run
npm run build --prefix apps/web
docker build -f Dockerfile.controller -t link42-audit-test .
```

专项测试中不启动 mimic 或 UDPspeeder；`shixcm` 上 mimic 服务保持 masked、无进程和监听端口。

### 12.2 本轮复核结果（2026-10-01）

本轮在修复剩余问题并补充健康检查回归后重新执行：

| 检查项 | 结果 |
|---|---|
| 后端/Agent 单测 | ✅ `.venv/bin/python -m pytest -q`：317 passed；仅有测试夹具和第三方库的弃用提示 |
| Python 编译 | ✅ `.venv/bin/python -m compileall -q apps/api apps/agent packages` |
| 差异格式检查 | ✅ `git diff --check` |
| 前端单测 | ✅ `npm test --prefix apps/web -- --run`：24 passed |
| 前端构建 | ✅ `npm run build --prefix apps/web`；最大单 chunk 约 427 KB，未出现单包告警 |
| 安全扫描 | ✅ 明文凭据扫描通过；`npm audit --audit-level=high` 通过，仍有 2 个 moderate 级 Vitest 开发依赖提示 |
| Docker 构建 | ✅ `docker build -f Dockerfile.controller -t link42-audit-test .` |
| Docker 启动冒烟 | ✅ `/api/health` 返回 `{"status":"ok"}`；容器 UID 为 0；`initial-admin-password` 权限为 0600；默认日志包含一次性密码 |
| mimic 状态 | ✅ `shixcm` 无 mimic 进程和监听端口，相关服务保持 `masked/inactive`；本轮未启动 mimic 或 UDPspeeder |

复核期间发现并修复一个由审计整改引入的回归：`health()` 使用数据库探针时遗漏 SQLAlchemy `text` 导入，导致 Docker 健康检查返回 503；已在 `tests/test_point_to_point_rules.py` 增加数据库健康探针测试。另修复了加密任务 payload 中 `plugin` 字段导致的 mimic 安装任务重复入队问题。
