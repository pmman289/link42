import React, { useCallback, useEffect, useRef, useState } from "react";
import { Database, Search, RefreshCw, Plus, ArrowRight, AlertTriangle, Network, ShieldCheck, X } from "lucide-react";
import { RequestGeneration, StaleRequestError } from "./requestGeneration";

export type IPAMRequest = <T>(path: string, options?: RequestInit) => Promise<T>;
type Pool = { id: number; name: string; cidr: string; kind: "node" | "link"; link_prefix: number };
type Recommendation = { addresses: string[]; subnet: string };
type NodeAddress = { id: number; name: string; internal_ipv4s?: string[] };
type Row = { source: string; node_id: number | null; id: number; type: "address" | "range"; address: string; node_name: string | null; interface_name: string | null; kind: string; state: string; conflict: boolean; note: string; can_release: boolean };
type Inventory = { items: Row[]; total: number; summary: { addresses: number; conflicts: number; retained: number; reservations: number }; nodes: { id: number; name: string }[] };
const sources: Record<string, string> = { node: "节点登记", wg: "WireGuard", gre: "GRE", candidate: "扫描发现", task: "Agent 任务", external: "人工登记", link: "子网分配" };

const labels: Record<string, string> = { fixed: "节点固定地址", tunnel: "隧道地址", deployed: "已部署", task: "未完成任务", observed: "扫描配置", external_peer: "外部对端", external: "外部占用 / 预留", link: "链路专用子网", assigned: "占用", retained: "待确认释放", reserved: "预留" };

export function replaceIPv4(current: string, addresses: string[]): string {
  const ipv6 = current.split(/[\s,]+/).filter((item) => item.includes(":"));
  return [...addresses, ...ipv6].join(", ");
}

function setField(form: HTMLFormElement, name: string, values: string[]) {
  const input = form.elements.namedItem(name);
  if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
    input.value = replaceIPv4(input.value, values);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

export function IPv4AllocationControls({ request, nodes = [], localNodeId, peerNodeId, fixedInput = false, initial = [] }: {
  request: IPAMRequest; nodes?: NodeAddress[]; localNodeId?: number | null; peerNodeId?: number | null; fixedInput?: boolean; initial?: string[];
}) {
  const [pools, setPools] = useState<Pool[]>([]);
  const [poolId, setPoolId] = useState("");
  const [mode, setMode] = useState("manual");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [poolRefresh, setPoolRefresh] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const generation = useRef(new RequestGeneration());
  const poolRequests = useRef(new RequestGeneration());
  const fillVersion = useRef(0);
  useEffect(() => {
    void poolRequests.current.run(async (assertCurrent) => {
      const data = await request<Pool[]>("/api/ipam/pools");
      assertCurrent();
      setPools(data.filter((pool) => pool.kind === (fixedInput ? "node" : "link")));
    }).catch((cause) => { if (!(cause instanceof StaleRequestError)) setError(String(cause.message || cause)); });
    return () => { poolRequests.current.invalidate(); generation.current.invalidate(); fillVersion.current += 1; };
  }, [request, fixedInput, poolRefresh]);

  function changeMode(value: string) {
    generation.current.invalidate();
    fillVersion.current += 1;
    setMode(value);
    setPoolId("");
    setBusy(false);
    setError("");
  }

  async function fill() {
    const form = root.current?.closest("form");
    if (!form) return;
    const version = ++fillVersion.current;
    setBusy(true);
    setError("");
    try {
      await generation.current.run(async (assertCurrent) => {
        if (!fixedInput && mode === "fixed") {
          const peerField = form.elements.namedItem("peer_node_id");
          const peerId = peerField instanceof HTMLSelectElement || peerField instanceof HTMLInputElement ? Number(peerField.value) : peerNodeId;
          const local = nodes.find((node) => node.id === localNodeId)?.internal_ipv4s?.[0];
          const peer = nodes.find((node) => node.id === peerId)?.internal_ipv4s?.[0];
          if (!local || (peerId && !peer)) throw new Error("请先为双方节点登记固定内网 /32 地址。");
          assertCurrent();
          setField(form, form.elements.namedItem("local_tunnel_ips") ? "local_tunnel_ips" : "tunnel_ips", [local]);
          if (peer) setField(form, "peer_tunnel_ips", [peer]);
        } else {
          if (!poolId) throw new Error("请选择地址池；可在 IPv4 地址管理中创建。");
          const data = await request<Recommendation>(`/api/ipam/pools/${poolId}/recommend`);
          assertCurrent();
          if (fixedInput) setField(form, "internal_ipv4s", data.addresses);
          else {
            setField(form, form.elements.namedItem("local_tunnel_ips") ? "local_tunnel_ips" : "tunnel_ips", [data.addresses[0]]);
            setField(form, "peer_tunnel_ips", [data.addresses[1]]);
          }
        }
      });
    } catch (cause) {
      if (!(cause instanceof StaleRequestError)) setError(cause instanceof Error ? cause.message : String(cause));
    } finally { if (version === fillVersion.current) setBusy(false); }
  }

  return <div className="ipamAllocation formWide" ref={root}>
    {fixedInput && <label>固定内网 IPv4（/32，可多条）<input name="internal_ipv4s" defaultValue={initial.join(", ")} placeholder="10.0.0.1/32" /></label>}
    <div className="ipamActions">
      {!fixedInput && <select aria-label="IPv4 分配方式" value={mode} onChange={(event) => changeMode(event.target.value)}>
        <option value="manual">手工填写 IPv4</option><option value="fixed">复用节点固定 /32</option><option value="pool">分配链路专用地址</option>
      </select>}
      {(fixedInput || mode === "pool") && <select aria-label="IPv4 地址池" value={poolId} onChange={(event) => { generation.current.invalidate(); fillVersion.current += 1; setPoolId(event.target.value); setBusy(false); }}>
        <option value="">选择地址池</option>{pools.map((pool) => <option key={pool.id} value={pool.id}>{pool.name} · {pool.cidr}{pool.kind === "link" ? ` · /${pool.link_prefix}` : ""}</option>)}
      </select>}
      {(fixedInput || mode !== "manual") && <button type="button" disabled={busy} onClick={() => void fill()}>{busy ? "查询中…" : mode === "fixed" ? "填入固定地址" : "推荐空闲地址"}</button>}
      {(fixedInput || mode === "pool") && <button type="button" disabled={busy} onClick={() => { setError(""); setPoolRefresh((value) => value + 1); }}>刷新地址池</button>}
    </div>
    {!fixedInput && <input type="hidden" name="ipv4_link_pool_id" value={mode === "pool" ? poolId : ""} />}
    {error && <p role="alert" className="ipamError">{error}</p>}
    <small className="muted">{fixedInput ? "仅登记地址；请自行配置节点系统。" : "填入时保留 IPv6。"} 推荐暂不占用地址，保存时确认并查重。</small>
  </div>;
}

export function IPAMPanel({ request, onClose }: { request: IPAMRequest; onClose: () => void }) {
  const [pools, setPools] = useState<Pool[]>([]);
  const [data, setData] = useState<Inventory>({ items: [], total: 0, summary: { addresses: 0, conflicts: 0, retained: 0, reservations: 0 }, nodes: [] });
  const [tab, setTab] = useState("inventory");
  const [query, setQuery] = useState("");
  const [state, setState] = useState("all");
  const [nodeId, setNodeId] = useState("");
  const [poolId, setPoolId] = useState("");
  const [offset, setOffset] = useState(0);
  const [kind, setKind] = useState("node");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [confirmRow, setConfirmRow] = useState<Row | null>(null);
  const [previews, setPreviews] = useState<Record<number, Recommendation>>({});
  const generation = useRef(new RequestGeneration());
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    generation.current.invalidate();
    setLoading(true);
    try {
      await generation.current.run(async (assertCurrent) => {
        const params = new URLSearchParams({ q: query, offset: String(offset), limit: "100", state });
        if (nodeId) params.set("node_id", nodeId);
        if (poolId) params.set("pool_id", poolId);
        const [poolData, inventory] = await Promise.all([
          request<Pool[]>("/api/ipam/pools"), request<Inventory>(`/api/ipam/inventory?${params}`),
        ]);
        assertCurrent();
        setPools(poolData); setData(inventory); setLoaded(true); setError(""); setLoading(false);
      });
    } catch (cause) {
      if (!(cause instanceof StaleRequestError) && mounted.current) {
        setLoading(false);
        throw cause;
      }
    }
  }, [request, query, offset, state, nodeId, poolId]);

  const refreshCurrent = useRef(refresh);
  refreshCurrent.current = refresh;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; generation.current.invalidate(); };
  }, []);
  useEffect(() => {
    generation.current.invalidate();
    setLoading(true);
    const timer = window.setTimeout(() => {
      void refresh().catch((cause) => setError(cause instanceof Error ? cause.message : String(cause)));
    }, 180);
    return () => { window.clearTimeout(timer); generation.current.invalidate(); };
  }, [refresh]);

  async function act(work: () => Promise<unknown>) {
    setBusy(true); setError("");
    try { await work(); if (mounted.current) { setPreviews({}); await refreshCurrent.current(); } }
    catch (cause) { if (!(cause instanceof StaleRequestError) && mounted.current) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { if (mounted.current) setBusy(false); }
  }

  function createPool(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const values = new FormData(form);
    void act(async () => {
      await request("/api/ipam/pools", { method: "POST", body: JSON.stringify({ name: values.get("name"), cidr: values.get("cidr"), kind, link_prefix: Number(values.get("link_prefix") || 30) }) });
      form.reset();
    });
  }
  function reserve(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const values = new FormData(form);
    void act(async () => { await request("/api/ipam/reservations", { method: "POST", body: JSON.stringify({ cidr: values.get("cidr"), note: values.get("note") }) }); form.reset(); });
  }
  function filterState(value: string) { setState(value); setOffset(0); setTab("inventory"); }
  function resetFilters() { setQuery(""); setState("all"); setNodeId(""); setPoolId(""); setOffset(0); }
  async function preview(pool: Pool) {
    setBusy(true); setError("");
    try {
      const result = await request<Recommendation>(`/api/ipam/pools/${pool.id}/recommend`);
      if (mounted.current) setPreviews((current) => ({ ...current, [pool.id]: result }));
    } catch (cause) { if (mounted.current) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { if (mounted.current) setBusy(false); }
  }
  const filtered = Boolean(query || state !== "all" || nodeId || poolId);

  return <div className="modalBackdrop" role="presentation"><section className="modalPanel ipamPanel" role="dialog" aria-modal="true" aria-labelledby="ipam-title">
    <header className="modalHeader"><div><span className="ipamEyebrow"><Network size={14} />地址规划</span><h2 id="ipam-title">IPv4 地址管理</h2><p className="muted">先查占用，再为节点和链路分配地址。</p></div><div className="ipamHeaderActions"><button type="button" className="secondary" disabled={busy || loading} onClick={() => void refresh().catch((cause) => setError(String(cause.message || cause)))}><RefreshCw size={15} />刷新台账</button><button type="button" className="iconButton" aria-label="关闭" onClick={onClose}><X size={18} /></button></div></header>
    {error && <p role="alert" className="ipamError"><AlertTriangle size={16} />{error}</p>}
    <div className="ipamSummary" aria-label="地址占用概览">
      <button type="button" onClick={() => { resetFilters(); setTab("inventory"); }}><span>已记录 IPv4</span><strong>{loaded ? data.summary.addresses : "—"}</strong><small>按主机地址去重</small></button>
      <button type="button" className={data.summary.conflicts ? "hasConflict" : ""} onClick={() => { resetFilters(); filterState("conflict"); }}><span>地址冲突</span><strong>{loaded ? data.summary.conflicts : "—"}</strong><small>查看重复归属</small></button>
      <button type="button" onClick={() => { resetFilters(); filterState("retained"); }}><span>待确认释放</span><strong>{loaded ? data.summary.retained : "—"}</strong><small>原设备清理后回收</small></button>
      <button type="button" onClick={() => { resetFilters(); filterState("external"); }}><span>外部预留</span><strong>{loaded ? data.summary.reservations : "—"}</strong><small>人工登记的 IP / 网段</small></button>
    </div>
    <nav className="ipamTabs" aria-label="地址管理视图">{[["inventory", "占用台账"], ["pools", "地址池"], ["reserve", "外部预留"]].map(([value, label]) => <button key={value} type="button" aria-current={tab === value ? "page" : undefined} onClick={() => setTab(value)}>{label}{value === "pools" && <span>{pools.length}</span>}</button>)}</nav>
    {tab === "inventory" && <section className="ipamSection" aria-labelledby="ipam-inventory-heading">
      <div className="ipamSectionTitle"><div><h3 id="ipam-inventory-heading">地址占用台账</h3><p className="muted">节点登记、隧道配置、部署快照和扫描候选自动汇入；同一地址可有多条来源记录。</p></div><span className="ipamCount">{data.total} 条记录</span></div>
      <div className="ipamFilters">
        <label className="ipamSearch"><Search size={17} /><input aria-label="搜索地址占用" value={query} onChange={(event) => { setOffset(0); setQuery(event.target.value); }} placeholder="搜索 IP、节点、接口或备注" /></label>
        <select aria-label="占用状态" value={state} onChange={(event) => filterState(event.target.value)}><option value="all">全部状态</option><option value="conflict">存在冲突</option><option value="assigned">正在占用</option><option value="retained">待确认释放</option><option value="reserved">全部预留子网</option><option value="external">外部预留</option></select>
        <select aria-label="所属节点" value={nodeId} onChange={(event) => { setNodeId(event.target.value); setOffset(0); }}><option value="">全部节点</option>{data.nodes.map((node) => <option key={node.id} value={node.id}>{node.name || `节点 #${node.id}`}</option>)}</select>
        <select aria-label="所属地址池" value={poolId} onChange={(event) => { setPoolId(event.target.value); setOffset(0); }}><option value="">全部地址池</option>{pools.map((pool) => <option key={pool.id} value={pool.id}>{pool.name} · {pool.cidr}</option>)}</select>
        {filtered && <button type="button" className="secondary" onClick={resetFilters}>重置筛选</button>}
      </div>
      <div className="ipamTable" aria-busy={loading}><table><thead><tr><th>地址 / 网段</th><th>节点 / 接口</th><th>用途与来源</th><th>状态</th><th>操作</th></tr></thead><tbody>{data.items.map((row) => <tr key={`${row.type}:${row.id}`} className={row.conflict ? "ipamConflict" : ""}>
        <td><code className="ipamAddress">{row.address}</code></td><td><strong>{row.node_name || (row.kind === "external_peer" ? "外部对端" : "—")}</strong>{row.interface_name && <small>{row.interface_name}</small>}{row.note && <small className="muted">{row.note}</small>}</td>
        <td>{labels[row.kind] || row.kind}<small className="muted">{sources[row.source] || "历史记录"}</small></td><td><div className="ipamBadges">{row.conflict && <span className="ipamBadge conflict"><AlertTriangle size={12} />冲突</span>}<span className={`ipamBadge ${row.state}`}>{labels[row.state] || row.state}</span></div></td><td>{row.can_release ? <button type="button" className="secondary" disabled={busy || loading} onClick={() => setConfirmRow(row)}>释放</button> : <span className="muted">—</span>}</td>
      </tr>)}</tbody></table>{data.items.length === 0 && <div className="ipamEmpty"><Database size={28} /><strong>{loading ? "正在读取地址记录…" : filtered ? "没有匹配的占用记录" : "还没有 IPv4 地址记录"}</strong><p>{filtered ? "调整筛选条件，或搜索其他 IP。" : "已有隧道配置会自动登记；也可在节点表单登记固定地址。"}</p>{filtered && <button type="button" className="secondary" onClick={resetFilters}>清除筛选</button>}</div>}</div>
      <div className="ipamPagination"><span className="muted" role="status">{loading ? "正在刷新…" : `显示 ${data.total ? offset + 1 : 0}–${Math.min(offset + 100, data.total)} 条，共 ${data.total} 条`}</span><div><button type="button" className="secondary" disabled={loading || offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>上一页</button><button type="button" className="secondary" disabled={loading || offset + 100 >= data.total} onClick={() => setOffset(offset + 100)}>下一页</button></div></div>
    </section>}
    {tab === "pools" && <section className="ipamSection" aria-labelledby="ipam-pools-heading">
      <div className="ipamSectionTitle"><div><h3 id="ipam-pools-heading">规划地址池</h3><p className="muted">节点池分配固定 /32，链路池分配独占 /30 或 /31 子网；各池网段不能重叠。</p></div></div>
      {pools.length === 0 && <div className="ipamEmpty"><Network size={28} /><strong>创建第一个地址池</strong><p>现有配置无需建池即可查重；地址池用于推荐空闲地址。</p></div>}
      <div className="ipamPools">{pools.map((pool) => <article className="ipamPoolCard" key={pool.id}><div className="ipamPoolHeading"><span className="ipamBadge assigned">{pool.kind === "node" ? "节点 /32" : `链路 /${pool.link_prefix}`}</span><button type="button" className="secondary" disabled={busy} onClick={() => { if (poolId === String(pool.id)) setPoolId(""); void act(() => request(`/api/ipam/pools/${pool.id}`, { method: "DELETE" })); }}>删除空池</button></div><h4>{pool.name}</h4><code>{pool.cidr}</code><div className="ipamPoolActions"><button type="button" className="secondary" onClick={() => { resetFilters(); setPoolId(String(pool.id)); setTab("inventory"); }}>查看占用<ArrowRight size={14} /></button><button type="button" className="secondary" disabled={busy || loading} onClick={() => void preview(pool)}>查看空闲推荐</button></div>{previews[pool.id] && <p className="ipamPreview"><strong>{previews[pool.id].addresses.join(" · ")}</strong><small>仅预览；在节点或连接表单保存时确认分配。</small></p>}</article>)}</div>
      <form className="ipamEditor" onSubmit={createPool}><div><h4><Plus size={16} />创建地址池</h4><p className="muted">填写可用于内网编址的完整网段，例如 10.100.0.0/24。</p></div><div className="ipamFormGrid"><label>名称<input aria-label="地址池名称" name="name" placeholder="例如：节点固定地址" maxLength={80} required /></label><label>网段 CIDR<input aria-label="地址池网段" name="cidr" placeholder="10.100.0.0/24" required /></label><label>用途<select aria-label="地址池类型" value={kind} onChange={(event) => setKind(event.target.value)}><option value="node">节点地址池 · /32</option><option value="link">链路地址池</option></select></label>{kind === "link" && <label>链路子网<select aria-label="链路前缀" name="link_prefix" defaultValue="30"><option value="30">/30 · 两个可用地址</option><option value="31">/31 · 点对点地址</option></select></label>}</div><button disabled={busy || loading}><Plus size={15} />创建地址池</button></form>
    </section>}
    {tab === "reserve" && <section className="ipamSection" aria-labelledby="ipam-reserve-heading"><div className="ipamSectionTitle"><div><h3 id="ipam-reserve-heading">登记外部占用</h3><p className="muted">记录项目外的设备地址或预留网段，推荐和保存时都会避开。</p></div><ShieldCheck size={24} /></div><form className="ipamEditor" onSubmit={reserve}><div className="ipamFormGrid"><label>IP 或网段<input aria-label="外部地址或网段" name="cidr" placeholder="10.100.0.10 或 10.102.0.0/24" required /></label><label>用途 / 所属设备<input aria-label="占用说明" name="note" placeholder="例如：现有路由器 Loopback" maxLength={500} required /></label></div><button disabled={busy || loading}><Plus size={15} />登记</button></form><button type="button" className="secondary" onClick={() => { resetFilters(); filterState("external"); }}>查看已登记预留<ArrowRight size={14} /></button></section>}
    {confirmRow && <div className="ipamRelease" role="region" aria-label="释放确认"><h4>确认释放 {confirmRow.address}</h4><p>请确认该地址或网段已从原设备清理，且不会再次启用。</p><div className="ipamActions"><button type="button" className="danger" disabled={busy} onClick={() => void act(async () => { await request(`/api/ipam/${confirmRow.type === "range" ? "reservations" : "claims"}/${confirmRow.id}/release`, { method: "POST", body: JSON.stringify({ confirmed_cleaned: true }) }); setConfirmRow(null); })}>确认已清理并释放</button><button type="button" className="secondary" disabled={busy} onClick={() => setConfirmRow(null)}>取消</button></div></div>}
    <footer className="ipamFootnote"><Database size={16} /><div>自动读取主控已知的节点与隧道地址。系统网卡 / Loopback 未上报的地址，请人工登记。<br />停止接口或删除面板记录仍保留占用；主机清理成功且没有引用后自动释放。</div></footer>
  </section></div>;
}
