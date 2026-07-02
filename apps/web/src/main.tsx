import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, ChevronDown, ChevronRight, GitBranch, LineChart as LineChartIcon, LogOut, Pencil, Plus, RefreshCw, Server, Settings, Upload, X } from "lucide-react";
import { Background, MarkerType, ReactFlow, type Edge as FlowEdge, type EdgeMouseHandler, type Node as FlowNode, type NodeMouseHandler, type OnNodeDrag } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import CreatableSelect from "react-select/creatable";
import type { SingleValue, StylesConfig } from "react-select";
import "./styles.css";

type NodeItem = {
  id: number;
  name: string;
  hostname: string | null;
  region: string | null;
  management_ip: string | null;
  public_ip: string | null;
  endpoint_ips: string[];
  topology_endpoint: string | null;
  github_proxy_url: string | null;
  topology_x: number | null;
  topology_y: number | null;
  topology_locked: boolean;
  agent_token_value: string | null;
  agent_version: string | null;
  agent_protocol_version: number | null;
  agent_capabilities: string[];
  agent_platform: Record<string, unknown>;
  agent_update_status: string | null;
  agent_last_error: string | null;
  middleware_install_status: string | null;
  status: string;
  last_seen_at: string | null;
};

type ConfigItem = {
  id: number;
  node_id: number;
  name: string;
  tunnel_ips: string[];
  listen_port: number | null;
  private_key_value: string | null;
  public_key: string | null;
  mtu: number | null;
  source: string;
  managed: boolean;
  enabled: boolean;
  table_name: string | null;
  interface_custom_config: string | null;
  runtime_status: string;
  primary_peer_endpoint_host: string | null;
  primary_peer_endpoint_port: number | null;
  primary_peer_allowed_ips: string[];
  monitor_summary: LinkMonitorSummary | null;
  warnings: string[];
};

type LinkMonitorSummary = {
  monitor_id: number;
  target_host: string;
  last_latency_ms: number | null;
  avg_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
  jitter_ms: number | null;
  packet_loss: number;
  stability_score: number;
  status: "healthy" | "warning" | "critical" | "unknown";
  sample_count: number;
  last_checked_at: string | null;
};

type LinkMonitor = {
  id: number;
  node_id: number;
  interface_id: number | null;
  name: string;
  target_host: string;
  interval_seconds: number;
  retention_days: number;
  enabled: boolean;
  next_due_at: string | null;
  last_checked_at: string | null;
  summary: LinkMonitorSummary | null;
};

type LinkMonitorSample = {
  checked_at: string;
  success: boolean;
  latency_ms: number | null;
  error: string | null;
};

type LinkMonitorSamplesResponse = {
  monitor: LinkMonitor;
  summary: LinkMonitorSummary | null;
  samples: LinkMonitorSample[];
};

type TopologyNode = {
  id: number;
  name: string;
  status: string;
  hostname: string | null;
  region: string | null;
  endpoint_ips: string[];
  topology_endpoint: string | null;
  agent_version: string | null;
  agent_platform: Record<string, unknown>;
  topology_x: number | null;
  topology_y: number | null;
  topology_locked: boolean;
};

type TopologyEdge = {
  id: string;
  local_node_id: number;
  peer_node_id: number;
  local_interface_id: number;
  peer_interface_id: number;
  local_interface_name: string;
  peer_interface_name: string;
  local_status: string;
  peer_status: string;
  middleware_type: string | null;
  local_monitor: LinkMonitorSummary | null;
  peer_monitor: LinkMonitorSummary | null;
};

type TopologyResponse = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
};

type PeerItem = {
  id: number;
  interface_id: number;
  name: string | null;
  public_key: string;
  preshared_key_value: string | null;
  allowed_ips: string[];
  endpoint_host: string | null;
  endpoint_port: number | null;
  persistent_keepalive: number | null;
  peer_custom_config: string | null;
  peer_node_id: number | null;
  peer_interface_id: number | null;
};

type ManagedLink = {
  local_interface: ConfigItem;
  peer_interface: ConfigItem;
  local_peer: PeerItem;
  peer_peer: PeerItem;
  middleware: MiddlewareConfig | null;
};

type MiddlewareConfig = Udp2RawMiddleware | MimicMiddleware;

type Udp2RawMiddleware = {
  type: "udp2raw";
  enabled: boolean;
  server_side: "local" | "peer";
  server_listen_host: string;
  server_connect_host: string | null;
  server_listen_port: number;
  server_forward_host: string | null;
  server_forward_port: number | null;
  client_listen_host: string;
  client_listen_port: number;
  raw_mode: string;
  cipher_mode: string;
  password: string;
  auto_rule: boolean;
};

type MimicMiddleware = {
  type: "mimic";
  enabled: boolean;
  local_bind_interface: string;
  peer_bind_interface: string;
  xdp_mode: "auto" | "native" | "skb";
  link_type: string;
  handshake_interval: number | null;
  keepalive_interval: number | null;
  padding: number | null;
};

type ChangePlan = {
  id: number;
  title: string;
  status: string;
  summary: string;
  diff: string;
  affected_node_ids: number[];
  task_status: string | null;
  task_result: Record<string, unknown> | null;
};

type TaskRequestResult = {
  task_id: number | null;
  status: string;
  message: string;
  result: Record<string, unknown> | null;
};

type AgentTaskStatus = {
  id: number;
  node_id: number;
  type: string;
  status: string;
  result: Record<string, unknown> | null;
};

type AgentUpgradePlan = {
  node_id: number;
  current_version: string | null;
  target_version: string | null;
  upgrade_mode: "self_upgrade" | "manual" | "none" | "unavailable";
  reason: string | null;
  matched_platform: string | null;
  matched_asset: { path: string; sha256: string; size: number | null } | null;
  manual_command: string | null;
  status: string | null;
};

type ImportCandidate = {
  id: number;
  node_id: number;
  path: string;
  interface_name: string;
  warnings: string[];
  imported: boolean;
};

type NodeCreateResult = {
  node: NodeItem;
  agent_token: string;
};

type LoginResult = {
  token: string;
  username: string;
};

type ControllerSettings = {
  controller_url: string;
  username: string;
  site_title: string;
  site_logo_url: string;
};

type BrandingSettings = {
  site_title: string;
  site_logo_url: string;
};

type Toast = {
  id: number;
  type: "success" | "error" | "info";
  text: string;
};

// API 基础路径；生产由 FastAPI 同源托管，Vite dev 通过 /api proxy 转发。
const INFERRED_API_BASE = "";
const API_BASE =
  import.meta.env.VITE_LINK42_API_BASE ||
  INFERRED_API_BASE;

// 默认主控地址；节点 Agent 从本机访问时通常使用 127.0.0.1。
const DEFAULT_CONTROLLER_URL =
  import.meta.env.VITE_LINK42_CONTROLLER_URL || API_BASE;
const DEFAULT_SITE_TITLE = "Link42";
const DEFAULT_SITE_LOGO_URL = "/logo.png";
const AUTH_TOKEN_KEY = "link42.authToken";
const AUTH_EXPIRED_EVENT = "link42:auth-expired";
const TASK_POLL_INTERVAL_MS = 2000;
const AGENT_TASK_POLL_LIMIT = 90;
const SHORT_TASK_POLL_LIMIT = 30;

function splitList(value: string): string[] {
  // 将输入框中的逗号或换行分隔内容转换成 API 需要的数组；不要按冒号切分，IPv6 会用到 "::"。
  return value
    .split(/[,\n]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function optionalInt(value: FormDataEntryValue | null): number | null {
  const text = String(value || "").trim();
  return text ? Number(text) : null;
}

async function api<T>(path: string, options?: RequestInit & { skipAuth?: boolean }): Promise<T> {
  // 统一封装 fetch，集中处理 JSON 和错误信息。
  const token = options?.skipAuth ? "" : window.localStorage.getItem(AUTH_TOKEN_KEY);
  const { skipAuth: _skipAuth, ...fetchOptions } = options || {};
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(fetchOptions.headers || {}),
    },
    ...fetchOptions,
  });
  if (!response.ok) {
    const text = await response.text();
    if (response.status === 401 && path !== "/api/auth/login") {
      window.localStorage.removeItem(AUTH_TOKEN_KEY);
      window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
    }
    throw new Error(formatApiError(response.status, text, response.statusText));
  }
  return response.json() as Promise<T>;
}

function formatApiError(status: number, body: string, fallback: string): string {
  // FastAPI 错误通常放在 detail 字段，这里转成用户能直接理解的提示。
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed.detail === "string") {
      return `${status}: ${translateApiDetail(parsed.detail)}`;
    }
    if (Array.isArray(parsed.detail)) {
      return `${status}: ${parsed.detail
        .map((item: { msg?: string }) => item.msg || JSON.stringify(item))
        .join("; ")}`;
    }
  } catch {
    // 非 JSON 响应直接走下面的兜底文本。
  }
  return `${status}: ${body || fallback}`;
}

function translateApiDetail(detail: string): string {
  // 后端 detail 保持稳定英文，前端负责给中文界面补充可读提示。
  const messages: Record<string, string> = {
    "agent is offline": "Agent 离线，节点当前不能执行部署或扫描任务",
    "node name already exists": "节点名称已存在",
    "node not found": "节点不存在",
    "interface name already exists on node": "该节点上已存在同名 WireGuard 配置",
    "deployable wireguard config must have exactly one enabled peer":
      "可部署配置必须且只能有一个启用对端",
    "change plan is not draft": "该部署计划已被确认或已结束，不能重复执行",
    "change plan has no task payload": "部署计划缺少 Agent 任务内容",
    "change plan has no diff": "当前计划没有 diff，无需下发任务",
    "wireguard config must be deployed before start": "WireGuard 配置需要先部署再启动",
    "OpenWrt UCI nodes do not support wg-quick import scan": "OpenWrt/UCI 节点不支持 wg-quick 文件导入扫描",
    "wireguard interface must be stopped before delete": "删除前必须先断开对应 WireGuard 连接",
    "peer node must be different": "请选择另一个节点作为对端",
    "local node has no endpoint address": "当前节点缺少可作为 Endpoint 的地址",
    "peer node has no endpoint address": "对端节点缺少可作为 Endpoint 的地址",
    "local endpoint address is not registered on node": "本端入口地址不属于当前节点",
    "peer endpoint address is not registered on node": "对端入口地址不属于所选节点",
    "wireguard tool is not installed": "主控缺少 wg 工具，无法自动生成密钥",
    "managed node links are deployed directly": "受管连接由系统直接下发，不使用部署计划",
    "use managed link operation": "受管连接需要使用双端操作",
    "wireguard config is not a managed node link": "该配置不是受管节点连接",
    "local imported endpoint does not point to peer node": "本端导入配置的 Endpoint 不指向所选对端节点",
    "peer imported endpoint does not point to local node": "对端导入配置的 Endpoint 不指向当前节点",
    "node has wireguard configs": "节点下仍有 WireGuard 配置，请先删除所有配置",
    "not authenticated": "请先登录",
    "invalid username or password": "用户名或密码错误",
    "controller url is required": "请填写主控访问地址",
  };
  return messages[detail] || detail;
}

function isNodeSelectable(node: NodeItem): boolean {
  // 只有 Agent 在线的节点才允许进入 WireGuard 下级菜单。
  return node.status === "online";
}

function nodeCapabilities(node: NodeItem | null): Set<string> {
  return new Set(node?.agent_capabilities || []);
}

function nodeServiceManager(node: NodeItem | null): string {
  const serviceManager = String(node?.agent_platform?.service_manager || "");
  if (serviceManager) return serviceManager;
  const capabilities = nodeCapabilities(node);
  if (capabilities.has("service:openwrt-uci")) return "openwrt-uci";
  if (capabilities.has("service:systemd")) return "systemd";
  if (capabilities.has("service:openrc")) return "openrc";
  if (capabilities.has("service:direct-wg-quick")) return "direct-wg-quick";
  return "";
}

function nodeSystemLabel(node: NodeItem | null): string {
  const labels: Record<string, string> = {
    "openwrt-uci": "OpenWrt / UCI",
    systemd: "Linux / systemd",
    openrc: "Linux / OpenRC",
    "direct-wg-quick": "Linux / wg-quick",
  };
  const serviceManager = nodeServiceManager(node);
  return labels[serviceManager] || serviceManager || "未知服务管理器";
}

function nodeSupportsWgQuickImport(node: NodeItem | null): boolean {
  return nodeCapabilities(node).has("wg_quick_import") && nodeServiceManager(node) !== "openwrt-uci";
}

function mimicPluginStatus(node: NodeItem | null): { label: string; detail: string; installable: boolean; installed: boolean; rebootRequired: boolean } {
  const capabilities = nodeCapabilities(node);
  const platform = node?.agent_platform || {};
  const middlewareStatus = String(node?.middleware_install_status || "");
  const rebootRequired = middlewareStatus === "mimic_reboot_required" || platform.mimic_reboot_required === true;
  if (rebootRequired) {
    return {
      label: "需要重启",
      detail: "mimic 已安装，但 DKMS 模块构建在新内核上；重启节点进入新内核后生效。",
      installable: false,
      installed: false,
      rebootRequired: true,
    };
  }
  if (!node || node.status !== "online") {
    return { label: "未知", detail: "节点离线，无法判断 mimic 安装状态。", installable: false, installed: false, rebootRequired: false };
  }
  if (capabilities.has("middleware.mimic")) {
    return { label: "已安装", detail: "Agent 已检测到 mimic，可在受管连接中启用。", installable: false, installed: true, rebootRequired: false };
  }
  if (capabilities.has("middleware.install.mimic")) {
    return { label: "可安装", detail: "将从 hack3ric/mimic 官方 GitHub latest release 下载。", installable: true, installed: false, rebootRequired: false };
  }
  return { label: "不支持", detail: "需要非 OpenWrt、systemd、Linux kernel > 6.1、Debian/Ubuntu 且 Agent 支持安装器。", installable: false, installed: false, rebootRequired: false };
}

function importScanUnavailableMessage(node: NodeItem | null, online: boolean): string {
  if (!online) {
    return "Agent 在线并上报能力后显示导入扫描。";
  }
  if (nodeServiceManager(node) === "openwrt-uci") {
    return "OpenWrt/UCI 节点不支持 wg-quick 文件导入。";
  }
  if (!node?.agent_capabilities?.length) {
    return "Agent 上报能力后显示可用的导入方式。";
  }
  return "当前节点未上报 wg-quick 文件导入能力。";
}

function statusLabel(status: string): string {
  // 统一把运行状态转换成界面文案。
  const labels: Record<string, string> = {
    running: "已连接",
    stopped: "已断开",
    starting: "启动中",
    stopping: "断开中",
    unknown: "未知",
  };
  return labels[status] || status;
}

function monitorTone(status: string | undefined) {
  if (status === "healthy") return "healthy";
  if (status === "warning") return "warning";
  if (status === "critical") return "critical";
  return "unknown";
}

function formatLatency(value: number | null | undefined) {
  return typeof value === "number" ? `${Math.round(value)}ms` : "--";
}

function formatLoss(value: number | null | undefined) {
  return typeof value === "number" ? `${(value * 100).toFixed(value > 0.01 ? 1 : 0)}%` : "--";
}

function topologyEdgeTone(edge: TopologyEdge): "healthy" | "warning" | "critical" | "unknown" {
  if (edge.local_status !== "running" || edge.peer_status !== "running") return "critical";
  const statuses = [edge.local_monitor?.status, edge.peer_monitor?.status].filter(Boolean);
  if (statuses.includes("critical")) return "critical";
  if (statuses.includes("warning")) return "warning";
  if (statuses.includes("healthy")) return "healthy";
  return "unknown";
}

function topologyEdgeSummary(edge: TopologyEdge) {
  const summary = edge.local_monitor || edge.peer_monitor;
  if (!summary) return "-- / --";
  return `${formatLatency(summary.last_latency_ms)} / ${formatLoss(summary.packet_loss)}`;
}

function topologyNodeEndpoint(node: TopologyNode) {
  return node.topology_endpoint || node.endpoint_ips[0] || node.hostname || "未配置地址";
}

function nodeRegionLabel(node: Pick<NodeItem, "region">) {
  return node.region?.trim() || "未设置地域";
}

function firstIpFromCidrs(values: string[]) {
  for (const value of values) {
    const text = value.split("/")[0]?.trim();
    if (text && isProbablyIpAddress(text)) return text;
  }
  return "";
}

function suggestedMonitorTarget(config: ConfigItem, peer: PeerItem | null) {
  return firstIpFromCidrs(peer?.allowed_ips || []) || firstIpFromCidrs(config.primary_peer_allowed_ips || []) || "";
}

function isValidPort(value: number | null): boolean {
  // UDP 端口范围校验，空值表示不填写。
  return value === null || (Number.isInteger(value) && value >= 1 && value <= 65535);
}

function isValidMtu(value: number | null): boolean {
  return value === null || (Number.isInteger(value) && value >= 576 && value <= 9000);
}

function isProbablyIpAddress(value: string): boolean {
  const cleaned = value.trim();
  if (!cleaned) return false;
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(cleaned) || (cleaned.includes(":") && ipv6.test(cleaned));
}

function isValidCidrs(values: string[]): boolean {
  // 用浏览器内置 URL/IP 能力不足，这里做轻量 CIDR 形态校验，后续可替换为严格解析器。
  return values.every((value) => /^([0-9a-fA-F:.]+)\/\d{1,3}$/.test(value));
}

function MonitorSummaryButton({
  summary,
  onClick,
}: {
  summary: LinkMonitorSummary | null;
  onClick: (event: React.MouseEvent<HTMLSpanElement>) => void;
}) {
  const tone = monitorTone(summary?.status);
  return (
    <span
      className={`monitorSummary ${tone}`}
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onClick(event as unknown as React.MouseEvent<HTMLSpanElement>);
        }
      }}
      title="查看链路延迟统计"
    >
      {summary ? (
        <>
          <span><strong>{formatLatency(summary.last_latency_ms)}</strong><small>延迟</small></span>
          <span><strong>{formatLoss(summary.packet_loss)}</strong><small>丢包</small></span>
          <span><strong>{summary.stability_score}</strong><small>稳定</small></span>
        </>
      ) : (
        <span><strong>未监测</strong><small>点击配置</small></span>
      )}
    </span>
  );
}

function isProbablyWireGuardKey(value: FormDataEntryValue | null): boolean {
  // WireGuard key 是 base64 字符串，常见长度 44；留空由调用方决定是否允许。
  if (!value) return true;
  return /^[A-Za-z0-9+/]{43}=$/.test(String(value));
}

function nodeEndpointOptions(node: NodeItem): string[] {
  // 新节点使用 endpoint_ips；旧库数据用历史字段兜底展示。
  return Array.from(new Set([
    ...(node.endpoint_ips || []),
    node.public_ip,
    node.management_ip,
    node.hostname,
  ].filter(Boolean) as string[]));
}

type EndpointOption = {
  value: string;
  label: string;
  source: "imported" | "node" | "current";
};

const endpointSelectStyles: StylesConfig<EndpointOption, false> = {
  menuPortal: (base) => ({ ...base, zIndex: 80 }),
};

function uniqueEndpointOptions(options: EndpointOption[]): EndpointOption[] {
  // 同一个 host 只保留第一次出现的来源，确保原始导入 Endpoint 优先展示。
  const seen = new Set<string>();
  return options.filter((option) => {
    const value = option.value.trim();
    if (!value || seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

function endpointOptionsFrom(
  importedHost: string | null | undefined,
  nodeHosts: string[],
  currentHost?: string | null,
): EndpointOption[] {
  return uniqueEndpointOptions([
    ...(importedHost ? [{ value: importedHost, label: importedHost, source: "imported" as const }] : []),
    ...(currentHost ? [{ value: currentHost, label: currentHost, source: "current" as const }] : []),
    ...nodeHosts.map((host) => ({ value: host, label: host, source: "node" as const })),
  ]);
}

function endpointSourceLabel(source: EndpointOption["source"]) {
  if (source === "imported") return "原始 Endpoint";
  if (source === "current") return "当前配置";
  return "节点地址";
}

function buildAgentCommand(node: NodeItem, controllerUrl: string = DEFAULT_CONTROLLER_URL): string {
  if (!node.agent_token_value) return "";
  return [
    "curl -fsSL https://get.pmman.tech/sh/link42-agent.sh",
    "|",
    "sudo env",
    `LINK42_SERVER_URL=${shellArg(controllerUrl)}`,
    `LINK42_NODE_ID=${shellArg(String(node.id))}`,
    `LINK42_AGENT_TOKEN=${shellArg(node.agent_token_value)}`,
    "sh",
  ].join(" ");
}

function shellArg(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function Field({
  label,
  hint,
  wide = false,
  children,
}: {
  label: string;
  hint?: string;
  wide?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className={wide ? "field wideField" : "field"}>
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

function FormSection({
  title,
  hint,
  children,
  tone = "default",
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
  tone?: "default" | "middleware";
}) {
  return (
    <section className={`formSection wideField ${tone === "middleware" ? "middlewareSection" : ""}`}>
      <div className="formSectionHeader">
        <h3>{title}</h3>
        {hint && <p>{hint}</p>}
      </div>
      <div className="formSectionGrid">
        {children}
      </div>
    </section>
  );
}

function EndpointSelect({
  name,
  defaultValue,
  placeholder,
  options,
  disabled = false,
  locked = false,
}: {
  name: string;
  defaultValue: string;
  placeholder: string;
  options: EndpointOption[];
  disabled?: boolean;
  locked?: boolean;
}) {
  const [value, setValue] = useState(defaultValue);
  const [inputValue, setInputValue] = useState("");
  const selectedOption = useMemo<EndpointOption | null>(() => {
    if (!value) return null;
    return options.find((option) => option.value === value) || {
      value,
      label: "手动输入",
      source: "current",
    };
  }, [options, value]);

  useEffect(() => {
    setValue(defaultValue);
    setInputValue("");
  }, [defaultValue]);

  function handleChange(option: SingleValue<EndpointOption>) {
    setValue(option?.value || "");
    setInputValue("");
  }

  function handleCreate(inputValue: string) {
    setValue(inputValue.trim());
    setInputValue("");
  }

  function commitInputValue() {
    const cleaned = inputValue.trim();
    if (cleaned) {
      setValue(cleaned);
      setInputValue("");
    }
  }

  return (
    <div className="endpointSelect">
      <CreatableSelect<EndpointOption, false>
        classNamePrefix="endpointSelect"
        value={selectedOption}
        options={options}
        isDisabled={disabled || locked}
        isClearable={false}
        inputValue={inputValue}
        placeholder={placeholder}
        noOptionsMessage={() => "没有可选地址，可直接输入"}
        formatCreateLabel={(inputValue) => `使用 "${inputValue}"`}
        onChange={handleChange}
        onCreateOption={handleCreate}
        onInputChange={(newValue, actionMeta) => {
          if (actionMeta.action === "input-change") {
            setInputValue(newValue);
          }
        }}
        onBlur={commitInputValue}
        menuPortalTarget={document.body}
        styles={endpointSelectStyles}
        formatOptionLabel={(option) => (
          <div className="endpointSelectOption">
            <span>{option.value}</span>
            <small>{endpointSourceLabel(option.source)}</small>
          </div>
        )}
      />
      <input
        type="hidden"
        name={name}
        value={value}
        disabled={disabled}
      />
      {locked && <small>由 udp2raw 接管</small>}
    </div>
  );
}

function MimicFields({
  enabled,
  defaults,
  localNode,
  peerNode,
  disabled,
  onEnabledChange,
}: {
  enabled: boolean;
  defaults?: Partial<MimicMiddleware> | null;
  localNode?: NodeItem | null;
  peerNode?: NodeItem | null;
  disabled?: boolean;
  onEnabledChange: (value: boolean) => void;
}) {
  const localInterfaces = interfaceOptions(localNode);
  const peerInterfaces = interfaceOptions(peerNode);
  function handleEnabledChange(event: React.ChangeEvent<HTMLInputElement>) {
    const nextEnabled = event.currentTarget.checked;
    onEnabledChange(nextEnabled);
    if (nextEnabled) {
      const mtuInput = event.currentTarget.form?.elements.namedItem("mtu");
      if (mtuInput instanceof HTMLInputElement) {
        mtuInput.value = "1408";
      }
    }
  }
  return (
    <FormSection
      title="mimic 透明中间层"
      hint="mimic 在 Linux 网卡层透明处理 WireGuard UDP 流量，不修改 Endpoint；需要非 OpenWrt、kernel > 6.1 且节点已安装 mimic。"
      tone="middleware"
    >
      <label className="checkField wideField">
        <input
          name="mimic_enabled"
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={handleEnabledChange}
        />
        <input type="hidden" name="mimic_enabled_state" value={enabled ? "on" : ""} disabled={disabled} />
        <span>启用 mimic</span>
      </label>
      {enabled && (
        <>
          <Field label="本端出口网卡" hint="选择承载本端 WireGuard Endpoint 流量的物理或上联网卡。">
            <select name="mimic_local_bind_interface" defaultValue={defaults?.local_bind_interface || localInterfaces[0] || ""} required disabled={disabled}>
              <option value="">请选择网卡</option>
              {localInterfaces.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </Field>
          <Field label="对端出口网卡" hint="选择承载对端 WireGuard Endpoint 流量的物理或上联网卡。">
            <select name="mimic_peer_bind_interface" defaultValue={defaults?.peer_bind_interface || peerInterfaces[0] || ""} required disabled={disabled}>
              <option value="">请选择网卡</option>
              {peerInterfaces.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </Field>
          <Field label="XDP 模式" hint="默认 skb 兼容性更稳；确认网卡 native XDP 稳定后可切 native。">
            <select name="mimic_xdp_mode" defaultValue={defaults?.xdp_mode || "skb"} disabled={disabled}>
              <option value="skb">skb</option>
              <option value="auto">auto</option>
              <option value="native">native</option>
            </select>
          </Field>
          <Field label="链路类型" hint="大多数以太网环境保持 eth。">
            <input name="mimic_link_type" defaultValue={defaults?.link_type || "eth"} disabled={disabled} />
          </Field>
          <Field label="Handshake 间隔" hint="映射为 mimic 的 handshake interval；留空使用 mimic 默认值。">
            <input name="mimic_handshake_interval" defaultValue={defaults?.handshake_interval || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <Field label="Keepalive 时间" hint="映射为 mimic 的 keepalive time；留空使用 mimic 默认值。">
            <input name="mimic_keepalive_interval" defaultValue={defaults?.keepalive_interval || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <Field label="Padding" hint="范围 0-16；留空不额外指定。">
            <input name="mimic_padding" defaultValue={defaults?.padding || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <div className="formNotice wideField">
            mimic 不会把 Endpoint 改为 127.0.0.1；请保持上方双方入口地址为真实可达地址，并确认防火墙放行对应 WireGuard 端口。
          </div>
        </>
      )}
    </FormSection>
  );
}

function interfaceOptions(node?: NodeItem | null): string[] {
  const platform = node?.agent_platform || {};
  const values = platform.network_interfaces;
  return Array.isArray(values) ? values.map((item) => String(item)).filter(Boolean) : [];
}

function RouteModeSelect({
  defaultValue = "off",
  disabled,
}: {
  defaultValue?: string | null;
  disabled?: boolean;
}) {
  return (
    <select name="table_name" defaultValue={defaultValue ?? "off"} disabled={disabled}>
      <option value="">自动生成路由（默认）</option>
      <option value="off">不自动生成路由（Table=off）</option>
    </select>
  );
}

function Udp2RawFields({
  enabled,
  serverSide,
  localListenPort,
  peerListenPort,
  defaults,
  disabled,
  onEnabledChange,
  onServerSideChange,
}: {
  enabled: boolean;
  serverSide: "local" | "peer";
  localListenPort?: number | null;
  peerListenPort?: number | null;
  defaults?: Partial<Udp2RawMiddleware> | null;
  disabled?: boolean;
  onEnabledChange: (value: boolean) => void;
  onServerSideChange: (value: "local" | "peer") => void;
}) {
  const serverWireGuardListenPort = serverSide === "local" ? localListenPort : peerListenPort;
  const forwardPortDefault = defaults?.server_forward_port || serverWireGuardListenPort || "";
  function handleEnabledChange(event: React.ChangeEvent<HTMLInputElement>) {
    const nextEnabled = event.currentTarget.checked;
    onEnabledChange(nextEnabled);
    if (nextEnabled) {
      const form = event.currentTarget.form;
      const mtuInput = form?.elements.namedItem("mtu");
      if (mtuInput instanceof HTMLInputElement) {
        mtuInput.value = "1300";
      }
    }
  }

  return (
    <FormSection
      title="udp2raw 连接中间层"
      hint="client 监听本机 UDP 并封装发往 server；server 收到后解包，再转发到本机 WireGuard UDP 端口。"
      tone="middleware"
    >
      <label className="checkField wideField">
        <input
          name="udp2raw_enabled"
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={handleEnabledChange}
        />
        <input type="hidden" name="udp2raw_enabled_state" value={enabled ? "on" : ""} disabled={disabled} />
        <span>启用 udp2raw</span>
      </label>
      {enabled && (
        <>
          <Field label="server 所在节点" hint="server 需要有 WireGuard ListenPort；client 侧 WireGuard 可不写 ListenPort。">
            <select
              name="udp2raw_server_side"
              value={serverSide}
              disabled={disabled}
              onChange={(event) => onServerSideChange(event.currentTarget.value as "local" | "peer")}
            >
              <option value="peer">对端运行 udp2raw server，本端运行 client</option>
              <option value="local">本端运行 udp2raw server，对端运行 client</option>
            </select>
          </Field>
          <Field label="client 连接 server IP" hint="写入 client 的 -r；必须是 IP，不能填域名。">
            <input name="udp2raw_server_connect_host" defaultValue={defaults?.server_connect_host || ""} placeholder="203.0.113.20" disabled={disabled} />
          </Field>
          <Field label="server 监听地址" hint="server 的 -l 地址；通常 0.0.0.0，必须是 IP。">
            <input name="udp2raw_server_listen_host" defaultValue={defaults?.server_listen_host || "0.0.0.0"} disabled={disabled} />
          </Field>
          <Field label="server 监听端口" hint="client 连接的 raw TCP/faketcp/icmp 端口。">
            <input name="udp2raw_server_listen_port" defaultValue={defaults?.server_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="server 转发到 IP" hint="server 解包后把 UDP 发往这里；通常 127.0.0.1。">
            <input name="udp2raw_server_forward_host" defaultValue={defaults?.server_forward_host || "127.0.0.1"} disabled={disabled} />
          </Field>
          <Field label="server 转发到端口" hint="可选；留空则使用 server 侧 WireGuard ListenPort。">
            <input
              key={`udp2raw-forward-port-${serverSide}-${forwardPortDefault}`}
              name="udp2raw_server_forward_port"
              defaultValue={forwardPortDefault}
              inputMode="numeric"
              disabled={disabled}
            />
          </Field>
          <Field label="client 本地监听地址" hint="WireGuard Endpoint 会被接管到这个本地 UDP 地址。">
            <input name="udp2raw_client_listen_host" defaultValue={defaults?.client_listen_host || "127.0.0.1"} disabled={disabled} />
          </Field>
          <Field label="client 本地监听端口" hint="填写本节点 WireGuard 连接对端接口时要使用的本地 udp2raw UDP 端口；本端 Peer Endpoint 会被接管到 127.0.0.1:此端口。">
            <input name="udp2raw_client_listen_port" defaultValue={defaults?.client_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="传输模式" hint="faketcp 伪装性更强；udp 更直接；icmp 仅在明确需要时使用。">
            <select name="udp2raw_raw_mode" defaultValue={defaults?.raw_mode || "faketcp"} disabled={disabled}>
              <option value="faketcp">faketcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </select>
          </Field>
          <Field label="加密模式" hint="xor 开销低；none 不加密；aes128cbc 兼容 udp2raw 原生模式。">
            <select name="udp2raw_cipher_mode" defaultValue={defaults?.cipher_mode || "xor"} disabled={disabled}>
              <option value="xor">xor</option>
              <option value="aes128cbc">aes128cbc</option>
              <option value="none">none</option>
            </select>
          </Field>
          <Field label="共享密码" hint="两端必须一致；留空时主控自动生成并保存。">
            <input name="udp2raw_password" defaultValue={defaults?.password || ""} disabled={disabled} />
          </Field>
          <label className="checkField wideField">
            <input name="udp2raw_auto_rule" type="checkbox" defaultChecked={defaults?.auto_rule ?? true} disabled={disabled} />
            <span>启用 udp2raw 自动规则（-a）</span>
          </label>
          <div className="formNotice wideField">
            {serverSide === "peer"
              ? "本端 Endpoint 会指向本端 udp2raw client；对端 server 解包后转发到对端 WireGuard。OpenWrt 作为 server 时，入口防火墙区域仍需手动放行 server 监听端口。"
              : "对端 Endpoint 会指向对端 udp2raw client；本端 server 解包后转发到本端 WireGuard。OpenWrt 作为 server 时，入口防火墙区域仍需手动放行 server 监听端口。"}
          </div>
        </>
      )}
    </FormSection>
  );
}

function readUdp2RawForm(
  form: FormData,
  localListenPort?: number | null,
  peerListenPort?: number | null,
): Record<string, unknown> | null {
  const enabled = form.get("udp2raw_enabled") === "on" || form.get("udp2raw_enabled_state") === "on";
  if (!enabled) return null;
  const serverSide = String(form.get("udp2raw_server_side") || "peer");
  const serverForwardPort =
    optionalInt(form.get("udp2raw_server_forward_port")) ??
    (serverSide === "local" ? localListenPort ?? null : peerListenPort ?? null);
  return {
    enabled: true,
    server_side: serverSide,
    server_listen_host: String(form.get("udp2raw_server_listen_host") || "0.0.0.0").trim(),
    server_connect_host: String(form.get("udp2raw_server_connect_host") || "").trim() || null,
    server_listen_port: optionalInt(form.get("udp2raw_server_listen_port")),
    server_forward_host: String(form.get("udp2raw_server_forward_host") || "127.0.0.1").trim(),
    server_forward_port: serverForwardPort,
    client_listen_host: String(form.get("udp2raw_client_listen_host") || "127.0.0.1").trim(),
    client_listen_port: optionalInt(form.get("udp2raw_client_listen_port")),
    raw_mode: String(form.get("udp2raw_raw_mode") || "faketcp"),
    cipher_mode: String(form.get("udp2raw_cipher_mode") || "xor"),
    password: String(form.get("udp2raw_password") || "").trim() || null,
    auto_rule: form.get("udp2raw_auto_rule") === "on",
  };
}

function readMimicForm(form: FormData): Record<string, unknown> | null {
  const enabled = form.get("mimic_enabled") === "on" || form.get("mimic_enabled_state") === "on";
  if (!enabled) return null;
  return {
    enabled: true,
    local_bind_interface: String(form.get("mimic_local_bind_interface") || "").trim(),
    peer_bind_interface: String(form.get("mimic_peer_bind_interface") || "").trim(),
    xdp_mode: String(form.get("mimic_xdp_mode") || "skb"),
    link_type: String(form.get("mimic_link_type") || "eth").trim() || "eth",
    handshake_interval: optionalInt(form.get("mimic_handshake_interval")),
    keepalive_interval: optionalInt(form.get("mimic_keepalive_interval")),
    padding: optionalInt(form.get("mimic_padding")),
  };
}

function validateMimicForm(mimic: Record<string, unknown> | null, localListenPort: number | null, peerListenPort: number | null) {
  if (!mimic) return;
  if (!mimic.local_bind_interface || !mimic.peer_bind_interface) {
    throw new Error("mimic 需要选择双方出口网卡");
  }
  if (!localListenPort || !peerListenPort) {
    throw new Error("mimic 透明匹配需要双方 WireGuard ListenPort 都填写");
  }
  if (!["auto", "native", "skb"].includes(String(mimic.xdp_mode))) {
    throw new Error("mimic XDP 模式必须是 auto、native 或 skb");
  }
  if (mimic.padding !== null && mimic.padding !== undefined) {
    const padding = Number(mimic.padding);
    if (!Number.isInteger(padding) || padding < 0 || padding > 16) {
      throw new Error("mimic padding 必须在 0-16 之间");
    }
  }
}

function validateUdp2RawForm(udp2raw: Record<string, unknown> | null, localListenPort: number | null, peerListenPort: number | null) {
  if (!udp2raw) return;
  const serverSide = String(udp2raw.server_side);
  const serverListenHost = String(udp2raw.server_listen_host || "");
  const serverConnectHost = String(udp2raw.server_connect_host || "");
  const serverForwardHost = String(udp2raw.server_forward_host || "");
  const clientListenHost = String(udp2raw.client_listen_host || "");
  if (
    !isValidPort(Number(udp2raw.server_listen_port) || null) ||
    !isValidPort(Number(udp2raw.client_listen_port) || null)
  ) {
    throw new Error("udp2raw server 监听端口和 client 本地 UDP 监听端口必须填写 1-65535 之间的整数");
  }
  if (!isValidPort(Number(udp2raw.server_forward_port) || null)) {
    throw new Error("udp2raw server 转发目的端口必须留空，或填写 1-65535 之间的整数");
  }
  if (!isProbablyIpAddress(serverListenHost) || !isProbablyIpAddress(serverForwardHost) || !isProbablyIpAddress(clientListenHost)) {
    throw new Error("udp2raw 监听地址和转发目的地址必须填写 IP，不能填写域名");
  }
  if (!isProbablyIpAddress(serverConnectHost)) {
    throw new Error("udp2raw server 对外地址必须填写 IP，不能填写域名");
  }
  if (serverSide === "local" && !localListenPort) {
    throw new Error("udp2raw server 在本端时，本端 WireGuard 监听端口必须填写");
  }
  if (serverSide === "peer" && !peerListenPort) {
    throw new Error("udp2raw server 在对端时，对端 WireGuard 监听端口必须填写");
  }
}

function App() {
  // Link42 第一版的主界面组件，集中承载节点和 WireGuard 管理流程。
  // 页面状态保持在顶层，第一版避免引入复杂状态管理。
  const [authToken, setAuthToken] = useState(() => window.localStorage.getItem(AUTH_TOKEN_KEY) || "");
  const [authChecked, setAuthChecked] = useState(false);
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [loginError, setLoginError] = useState("");
  const [controllerUrl, setControllerUrl] = useState(DEFAULT_CONTROLLER_URL);
  const [settingsUsername, setSettingsUsername] = useState("pmman");
  const [siteTitle, setSiteTitle] = useState(DEFAULT_SITE_TITLE);
  const [siteLogoUrl, setSiteLogoUrl] = useState(DEFAULT_SITE_LOGO_URL);
  const [settingsLogoPreviewUrl, setSettingsLogoPreviewUrl] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [topology, setTopology] = useState<TopologyResponse>({ nodes: [], edges: [] });
  const [topologyDraftPositions, setTopologyDraftPositions] = useState<Record<number, { x: number; y: number }>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const [configs, setConfigs] = useState<ConfigItem[]>([]);
  const [selectedConfigId, setSelectedConfigId] = useState<number | null>(null);
  const [peer, setPeer] = useState<PeerItem | null>(null);
  const [managedLink, setManagedLink] = useState<ManagedLink | null>(null);
  const [importCandidates, setImportCandidates] = useState<ImportCandidate[]>([]);
  const [plan, setPlan] = useState<ChangePlan | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [createDialog, setCreateDialog] = useState<"external" | "managed" | null>(null);
  const [nodeCreateOpen, setNodeCreateOpen] = useState(false);
  const [editingNodeId, setEditingNodeId] = useState<number | null>(null);
  const [agentUpgradePlan, setAgentUpgradePlan] = useState<AgentUpgradePlan | null>(null);
  const [managedPeerNodeId, setManagedPeerNodeId] = useState<number | null>(null);
  const [replaceLocalConfigId, setReplaceLocalConfigId] = useState<number | null>(null);
  const [replacePeerConfigId, setReplacePeerConfigId] = useState<number | null>(null);
  const [forceEndpointMismatch, setForceEndpointMismatch] = useState(false);
  const [middlewareType, setMiddlewareType] = useState<"none" | "udp2raw" | "mimic">("none");
  const [udp2rawEnabled, setUdp2rawEnabled] = useState(false);
  const [mimicEnabled, setMimicEnabled] = useState(false);
  const [udp2rawServerSide, setUdp2rawServerSide] = useState<"local" | "peer">("peer");
  const [managedCreateMtu, setManagedCreateMtu] = useState("1420");
  const [peerNodeConfigs, setPeerNodeConfigs] = useState<ConfigItem[]>([]);
  const [importCandidatesExpanded, setImportCandidatesExpanded] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteNodeConfig, setDeleteNodeConfig] = useState(false);
  const [monitorDialogConfigId, setMonitorDialogConfigId] = useState<number | null>(null);
  const [monitorWindow, setMonitorWindow] = useState("1h");
  const [monitorDetail, setMonitorDetail] = useState<LinkMonitorSamplesResponse | null>(null);
  const [pendingActions, setPendingActions] = useState<Set<string>>(() => new Set());
  const topologyEdgeSelectionRef = useRef<number | null>(null);
  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) || null,
    [nodes, selectedNodeId],
  );
  const nodeRegionGroups = useMemo(() => {
    const groups = new Map<string, NodeItem[]>();
    for (const node of nodes) {
      const region = nodeRegionLabel(node);
      groups.set(region, [...(groups.get(region) || []), node]);
    }
    return Array.from(groups.entries())
      .map(([region, items], index) => ({
        id: `node-region-${index}`,
        region,
        nodes: items,
        onlineCount: items.filter(isNodeSelectable).length,
      }))
      .sort((left, right) => {
        if (left.region === "未设置地域") return 1;
        if (right.region === "未设置地域") return -1;
        return left.region.localeCompare(right.region, "zh-Hans-CN");
      });
  }, [nodes]);
  const selectedConfig = useMemo(
    () => configs.find((item) => item.id === selectedConfigId) || null,
    [configs, selectedConfigId],
  );
  const monitorDialogConfig = useMemo(
    () => configs.find((item) => item.id === monitorDialogConfigId) || null,
    [configs, monitorDialogConfigId],
  );
  const selectedNodeOnline = selectedNode ? isNodeSelectable(selectedNode) : false;
  const editingNode = useMemo(
    () => nodes.find((node) => node.id === editingNodeId) || null,
    [nodes, editingNodeId],
  );
  const editingNodeMimicStatus = mimicPluginStatus(editingNode);
  const isConfigRunning = selectedConfig?.runtime_status === "running";
  const isConfigStopped = !selectedConfig || ["stopped", "unknown"].includes(selectedConfig.runtime_status);
  const isConfigBusy = selectedConfig ? ["starting", "stopping"].includes(selectedConfig.runtime_status) : false;
  const selectedConfigIsManagedLink = selectedConfig?.source === "managed-node";
  const selectedConfigIsUnmanagedImport = selectedConfig?.source === "imported" && !selectedConfig.managed;
  const selectedNodeSupportsWgQuickImport = nodeSupportsWgQuickImport(selectedNode);
  const hasDeployDiff = Boolean(plan?.diff.trim());
  const selectedPeerNodeOptions = selectedNode
    ? nodes.filter((item) => item.id !== selectedNode.id && isNodeSelectable(item))
    : [];
  const selectedManagedPeerNode = selectedPeerNodeOptions.find((item) => item.id === managedPeerNodeId) || null;
  const udp2rawActive = middlewareType === "udp2raw" && udp2rawEnabled;
  const mimicActive = middlewareType === "mimic" && mimicEnabled;
  const selectedLocalEndpoints = selectedNode ? nodeEndpointOptions(selectedNode) : [];
  const selectedPeerEndpoints = selectedManagedPeerNode ? nodeEndpointOptions(selectedManagedPeerNode) : [];
  const selectedManagedLinkPeerNode = managedLink
    ? nodes.find((node) => node.id === managedLink.peer_interface.node_id) || null
    : null;
  const actionPending = (key: string) => pendingActions.has(key);
  const nodeActionKey = (nodeId: number | null | undefined, action: string) => `node:${nodeId || "none"}:${action}`;
  const configActionKey = (configId: number | null | undefined, action: string) => `config:${configId || "none"}:${action}`;
  const monitorActionKey = (configId: number | null | undefined, action: string) => `monitor:${configId || "none"}:${action}`;
  const candidateActionKey = (candidateId: number) => `candidate:${candidateId}:import`;
  const selectedConfigAnyTaskPending = selectedConfigId
    ? [
        "create-plan",
        "refresh-deployed",
        "start",
        "stop",
        "delete",
        "confirm-plan",
        "take-over",
        "save-config",
        "save-peer",
        "save-managed-link",
      ].some((action) => actionPending(configActionKey(selectedConfigId, action)))
    : false;
  const selectedManagedLinkPeerEndpoints = selectedManagedLinkPeerNode
    ? nodeEndpointOptions(selectedManagedLinkPeerNode)
    : [];
  const replaceLocalConfig = replaceLocalConfigId
    ? configs.find((item) => item.id === replaceLocalConfigId) || null
    : null;
  const replacePeerConfigOptions = peerNodeConfigs.filter((item) => item.source === "imported" && !item.managed);
  const replacePeerConfig = replacePeerConfigId
    ? replacePeerConfigOptions.find((item) => item.id === replacePeerConfigId) || null
    : null;
  const managedLocalEndpointOptions = endpointOptionsFrom(
    replacePeerConfig?.primary_peer_endpoint_host,
    selectedLocalEndpoints,
  );
  const managedPeerEndpointOptions = endpointOptionsFrom(
    replaceLocalConfig?.primary_peer_endpoint_host,
    selectedPeerEndpoints,
  );
  const managedLocalEndpointDefault = managedLocalEndpointOptions[0]?.value || "";
  const managedPeerEndpointDefault = managedPeerEndpointOptions[0]?.value || "";
  const managedLocalAllowedIpsDefault = (replaceLocalConfig?.primary_peer_allowed_ips?.length
    ? replaceLocalConfig.primary_peer_allowed_ips
    : replacePeerConfig?.tunnel_ips || []).join(", ");
  const managedPeerAllowedIpsDefault = (replacePeerConfig?.primary_peer_allowed_ips?.length
    ? replacePeerConfig.primary_peer_allowed_ips
    : replaceLocalConfig?.tunnel_ips || []).join(", ");
  const editLocalEndpointOptions = endpointOptionsFrom(
    null,
    selectedLocalEndpoints,
    managedLink?.peer_peer.endpoint_host || selectedLocalEndpoints[0],
  );
  const editPeerEndpointOptions = endpointOptionsFrom(
    null,
    selectedManagedLinkPeerEndpoints,
    managedLink?.local_peer.endpoint_host || selectedManagedLinkPeerEndpoints[0],
  );
  const editLocalEndpointDefault = managedLink?.peer_peer.endpoint_host || selectedLocalEndpoints[0] || "";
  const editPeerEndpointDefault = managedLink?.local_peer.endpoint_host || selectedManagedLinkPeerEndpoints[0] || "";
  const topologyFlowNodes = useMemo<FlowNode[]>(() => {
    const count = Math.max(topology.nodes.length, 1);
    const radius = Math.max(180, Math.min(340, count * 42));
    return topology.nodes.map((node, index) => {
      const angle = (Math.PI * 2 * index) / count - Math.PI / 2;
      const draft = topologyDraftPositions[node.id];
      const x = draft?.x ?? node.topology_x ?? 420 + Math.cos(angle) * radius;
      const y = draft?.y ?? node.topology_y ?? 260 + Math.sin(angle) * radius;
      const online = node.status === "online";
      return {
        id: String(node.id),
        position: { x, y },
        data: {
          label: (
            <div className={online ? "topologyNode online" : "topologyNode"}>
              <div className="topologyNodeHeader">
                <strong>{node.name}</strong>
                <span className={online ? "statusDot online" : "statusDot"} />
              </div>
              <small>{node.region || "未设置地域"}</small>
              <span>{topologyNodeEndpoint(node)}</span>
            </div>
          ),
        },
        draggable: true,
        className: online ? "topologyFlowNode online" : "topologyFlowNode",
      };
    });
  }, [topology.nodes, topologyDraftPositions]);
  const topologyFlowEdges = useMemo<FlowEdge[]>(() =>
    topology.edges.map((edge) => {
      const tone = topologyEdgeTone(edge);
      return {
        id: edge.id,
        source: String(edge.local_node_id),
        target: String(edge.peer_node_id),
        label: topologyEdgeSummary(edge),
        animated: edge.local_status === "running" && edge.peer_status === "running",
        className: `topologyEdge ${tone}`,
        markerEnd: { type: MarkerType.ArrowClosed },
        data: edge,
      };
    }),
  [topology.edges]);

  const handleTopologyNodeClick: NodeMouseHandler = (_event, node) => {
    const nodeId = Number(node.id);
    setSelectedNodeId(nodeId);
    setSelectedConfigId(null);
    setPlan(null);
    setImportCandidatesExpanded(false);
    window.setTimeout(() => {
      document.querySelector(`[data-node-id="${nodeId}"]`)?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 180);
  };

  const handleTopologyNodeDragStop: OnNodeDrag = (_event, node) => {
    const nodeId = Number(node.id);
    void runAction(
      async () => {
        await saveTopologyPosition(nodeId, node.position.x, node.position.y);
        setTopologyDraftPositions((current) => {
          const next = { ...current };
          delete next[nodeId];
          return next;
        });
      },
      nodeActionKey(nodeId, "topology-position"),
    );
  };

  const handleTopologyNodeDrag: OnNodeDrag = (_event, node) => {
    const nodeId = Number(node.id);
    setTopologyDraftPositions((current) => ({
      ...current,
      [nodeId]: { x: node.position.x, y: node.position.y },
    }));
  };

  const handleTopologyEdgeClick: EdgeMouseHandler = (_event, edge) => {
    const data = edge.data as TopologyEdge | undefined;
    if (!data) return;
    topologyEdgeSelectionRef.current = data.local_node_id === selectedNodeId ? null : data.local_interface_id;
    setSelectedNodeId(data.local_node_id);
    setSelectedConfigId(data.local_interface_id);
    setPlan(null);
    window.setTimeout(() => {
      document.querySelector(`[data-config-id="${data.local_interface_id}"]`)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }, 180);
  };

  function notify(type: Toast["type"], text: string) {
    // 右上角 toast 避免把所有消息堆在主页主流程里。
    const id = Date.now() + Math.random();
    setToasts((items) => [...items, { id, type, text }]);
    window.setTimeout(() => {
      setToasts((items) => items.filter((item) => item.id !== id));
    }, type === "error" ? 6000 : 3800);
  }

  function resetManagedLinkDraft(overrides: { replaceLocalConfigId?: number | null } = {}) {
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(overrides.replaceLocalConfigId ?? null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setManagedCreateMtu("1420");
  }

  function closeCreateDialog() {
    setCreateDialog(null);
    resetManagedLinkDraft();
  }

  function openManagedCreateDialog(overrides: { replaceLocalConfigId?: number | null } = {}) {
    resetManagedLinkDraft(overrides);
    setCreateDialog("managed");
  }

  function clearAuthenticatedState() {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    setAuthToken("");
    setCurrentUser(null);
    setNodes([]);
    setTopology({ nodes: [], edges: [] });
    setTopologyDraftPositions({});
    setSelectedNodeId(null);
    setConfigs([]);
    setSelectedConfigId(null);
    setPeer(null);
    setManagedLink(null);
    setImportCandidates([]);
    setPlan(null);
    setCreateDialog(null);
    setNodeCreateOpen(false);
    setEditingNodeId(null);
    setAgentUpgradePlan(null);
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setManagedCreateMtu("1420");
    setPeerNodeConfigs([]);
    setSettingsOpen(false);
    setMonitorDialogConfigId(null);
    setMonitorDetail(null);
    setPendingActions(new Set());
  }

  function sleep(ms: number) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  async function runAction(action: () => Promise<void>, key?: string) {
    // 所有用户操作都通过这里展示 API 错误，避免点击后页面无反馈。
    if (key && pendingActions.has(key)) {
      return;
    }
    if (key) {
      setPendingActions((items) => {
        const next = new Set(items);
        next.add(key);
        return next;
      });
    }
    try {
      await action();
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("401:")) {
        clearAuthenticatedState();
        return;
      }
      notify("error", error instanceof Error ? error.message : String(error));
    } finally {
      if (key) {
        setPendingActions((items) => {
          const next = new Set(items);
          next.delete(key);
          return next;
        });
      }
    }
  }

  function holdActionPending(key: string) {
    setPendingActions((items) => {
      const next = new Set(items);
      next.add(key);
      return next;
    });
  }

  function releaseActionPending(key: string) {
    setPendingActions((items) => {
      const next = new Set(items);
      next.delete(key);
      return next;
    });
  }

  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setLoginError("");
    let result: LoginResult;
    try {
      result = await api<LoginResult>("/api/auth/login", {
        method: "POST",
        skipAuth: true,
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
        }),
      });
    } catch (error) {
      setLoginError(error instanceof Error ? error.message.replace(/^401:\s*/, "") : "登录失败");
      return;
    }
    window.localStorage.setItem(AUTH_TOKEN_KEY, result.token);
    setAuthToken(result.token);
    setCurrentUser(result.username);
    await refreshSettings();
    await refreshHome();
  }

  async function logout() {
    await api<{ status: string }>("/api/auth/logout", { method: "POST" });
    clearAuthenticatedState();
  }

  async function refreshSettings() {
    const data = await api<ControllerSettings>("/api/settings");
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(data.site_logo_url || DEFAULT_SITE_LOGO_URL);
  }

  async function refreshBranding() {
    const data = await api<BrandingSettings>("/api/branding", { skipAuth: true });
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(data.site_logo_url || DEFAULT_SITE_LOGO_URL);
  }

  async function saveSettings(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const newPassword = String(form.get("new_password") || "");
    if (newPassword && newPassword.length < 6) {
      throw new Error("新密码至少需要 6 个字符");
    }
    const logoFile = form.get("site_logo_file");
    let uploadedLogoUrl: string | null = null;
    if (logoFile instanceof File && logoFile.size > 0) {
      const logoSettings = await api<ControllerSettings>("/api/settings/logo", {
        method: "POST",
        headers: { "Content-Type": logoFile.type },
        body: logoFile,
      });
      uploadedLogoUrl = logoSettings.site_logo_url || DEFAULT_SITE_LOGO_URL;
    }
    const payload: {
      controller_url: string;
      username: string;
      site_title: string;
      new_password?: string;
    } = {
      controller_url: String(form.get("controller_url") || "").trim(),
      username: String(form.get("username") || "").trim(),
      site_title: String(form.get("site_title") || "").trim() || DEFAULT_SITE_TITLE,
    };
    if (newPassword) {
      payload.new_password = newPassword;
    }
    const data = await api<ControllerSettings>("/api/settings", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(uploadedLogoUrl || data.site_logo_url || DEFAULT_SITE_LOGO_URL);
    setSettingsLogoPreviewUrl("");
    setSettingsOpen(false);
    if (newPassword) {
      clearAuthenticatedState();
      notify("success", "账号已更新，请使用新凭据重新登录。");
      return;
    }
    setCurrentUser(data.username || currentUser);
    notify("success", "设置已保存。");
  }

  function previewLogoFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    setSettingsLogoPreviewUrl((previous) => {
      if (previous.startsWith("blob:")) {
        URL.revokeObjectURL(previous);
      }
      return file ? URL.createObjectURL(file) : "";
    });
  }

  async function refreshNodes() {
    // 刷新节点列表；节点必须由用户主动点选，离线节点不能进入下级菜单。
    const data = await api<NodeItem[]>("/api/nodes");
    setNodes(data);
  }

  async function refreshTopology() {
    const data = await api<TopologyResponse>("/api/topology");
    setTopology(data);
  }

  async function refreshHome() {
    await Promise.all([refreshNodes(), refreshTopology()]);
    if (selectedNodeId) {
      await refreshConfigs(selectedNodeId, selectedConfigId);
    }
    if (selectedConfigId) {
      await refreshPeer(selectedConfigId).catch(() => undefined);
      await refreshManagedLink(selectedConfigId).catch(() => undefined);
    }
    if (monitorDialogConfigId) {
      await refreshMonitorDetail(monitorDialogConfigId).catch(() => undefined);
    }
  }

  async function saveTopologyPosition(nodeId: number, x: number, y: number) {
    await api<NodeItem>(`/api/nodes/${nodeId}/topology-position`, {
      method: "PATCH",
      body: JSON.stringify({ x, y, locked: true }),
    });
    setTopology((current) => ({
      ...current,
      nodes: current.nodes.map((node) =>
        node.id === nodeId
          ? { ...node, topology_x: x, topology_y: y, topology_locked: true }
          : node,
      ),
    }));
    setNodes((current) =>
      current.map((node) =>
        node.id === nodeId
          ? { ...node, topology_x: x, topology_y: y, topology_locked: true }
          : node,
      ),
    );
  }

  async function resetTopologyLayout() {
    const data = await api<TopologyResponse>("/api/topology/layout/reset", { method: "POST" });
    setTopologyDraftPositions({});
    setTopology(data);
    setNodes((current) =>
      current.map((node) => ({
        ...node,
        topology_x: null,
        topology_y: null,
        topology_locked: false,
      })),
    );
    notify("success", "拓扑位置已还原为自动布局。");
  }

  async function refreshConfigs(nodeId: number, preferredConfigId?: number | null) {
    // 刷新某个节点下的 WireGuard 点对点配置列表。
    const data = await api<ConfigItem[]>(`/api/nodes/${nodeId}/wireguard/configs`);
    setConfigs(data);
    const existing = selectedConfigId && data.some((item) => item.id === selectedConfigId);
    if (preferredConfigId && data.some((item) => item.id === preferredConfigId)) {
      setSelectedConfigId(preferredConfigId);
    } else if (!existing) {
      setSelectedConfigId(null);
    }
  }

  async function refreshPeerNodeConfigs(nodeId: number) {
    const data = await api<ConfigItem[]>(`/api/nodes/${nodeId}/wireguard/configs`);
    setPeerNodeConfigs(data);
  }

  async function refreshPeer(configId: number) {
    // 刷新某个配置下的唯一对端；第一版一个配置只允许一个对端。
    const data = await api<PeerItem | null>(`/api/wireguard/configs/${configId}/peer`);
    setPeer(data);
  }

  async function refreshManagedLink(configId: number) {
    const data = await api<ManagedLink>(`/api/wireguard/configs/${configId}/managed-link`);
    setManagedLink(data);
  }

  async function refreshMonitorDetail(configId: number, windowValue = monitorWindow) {
    const monitor = await api<LinkMonitor | null>(`/api/wireguard/configs/${configId}/link-monitor`);
    if (!monitor) {
      setMonitorDetail(null);
      return;
    }
    const detail = await api<LinkMonitorSamplesResponse>(`/api/link-monitors/${monitor.id}/samples?window=${encodeURIComponent(windowValue)}`);
    setMonitorDetail(detail);
  }

  async function saveLinkMonitor(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!monitorDialogConfig || !selectedNodeId) return;
    const form = new FormData(event.currentTarget);
    await api<LinkMonitor>(`/api/wireguard/configs/${monitorDialogConfig.id}/link-monitor`, {
      method: "POST",
      body: JSON.stringify({
        target_host: String(form.get("target_host") || "").trim(),
        interval_seconds: optionalInt(form.get("interval_seconds")) ?? 10,
        retention_days: optionalInt(form.get("retention_days")) ?? 7,
        enabled: form.get("enabled") === "on",
      }),
    });
    await refreshMonitorDetail(monitorDialogConfig.id);
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", "链路监测已保存。");
  }

  async function deleteLinkMonitor() {
    if (!monitorDetail || !monitorDialogConfig || !selectedNodeId) return;
    await api<{ status: string }>(`/api/link-monitors/${monitorDetail.monitor.id}`, { method: "DELETE" });
    setMonitorDetail(null);
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", "链路监测已删除。");
  }

  async function refreshImportCandidates(nodeId: number) {
    // 刷新当前节点的 wg-quick 导入候选。
    const data = await api<ImportCandidate[]>(`/api/nodes/${nodeId}/wireguard/import-candidates`);
    setImportCandidates(data);
  }

  useEffect(() => {
    function handleAuthExpired() {
      clearAuthenticatedState();
    }

    window.addEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
  }, []);

  useEffect(() => {
    async function bootstrap() {
      if (!authToken) {
        await refreshBranding().catch(() => undefined);
        setAuthChecked(true);
        return;
      }
      try {
        const me = await api<{ authenticated: boolean; username: string | null }>("/api/auth/me");
        setCurrentUser(me.username);
        await refreshSettings();
        await refreshHome();
      } catch {
        clearAuthenticatedState();
      } finally {
        setAuthChecked(true);
      }
    }
    void bootstrap();
  }, [authToken]);

  useEffect(() => {
    if (!authToken) return;
    const timer = window.setInterval(() => {
      refreshHome().catch((error) => {
        if (!(error instanceof Error && error.message.startsWith("401:"))) {
          notify("error", error instanceof Error ? error.message : String(error));
        }
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [selectedNodeId, selectedConfigId, monitorDialogConfigId, monitorWindow, authToken]);

  useEffect(() => {
    document.title = siteTitle || DEFAULT_SITE_TITLE;
  }, [siteTitle]);

  useEffect(() => {
    return () => {
      if (settingsLogoPreviewUrl.startsWith("blob:")) {
        URL.revokeObjectURL(settingsLogoPreviewUrl);
      }
    };
  }, [settingsLogoPreviewUrl]);

  useEffect(() => {
    if (managedPeerNodeId) {
      refreshPeerNodeConfigs(managedPeerNodeId).catch((error) => notify("error", error.message));
    } else {
      setPeerNodeConfigs([]);
      setReplacePeerConfigId(null);
    }
  }, [managedPeerNodeId]);

  useEffect(() => {
    setImportCandidatesExpanded(false);
    if (selectedNodeId) {
      const preferredConfigId = topologyEdgeSelectionRef.current;
      topologyEdgeSelectionRef.current = null;
      if (!preferredConfigId) {
        setSelectedConfigId(null);
      }
      setPlan(null);
      setManagedPeerNodeId(null);
      refreshConfigs(selectedNodeId, preferredConfigId).catch((error) => notify("error", error.message));
      refreshImportCandidates(selectedNodeId).catch((error) => notify("error", error.message));
    } else {
      topologyEdgeSelectionRef.current = null;
      setConfigs([]);
      setSelectedConfigId(null);
      setImportCandidates([]);
      setPlan(null);
    }
  }, [selectedNodeId]);

  useEffect(() => {
    if (!editingNodeId || !authToken) {
      setAgentUpgradePlan(null);
      return;
    }
    refreshAgentUpgradePlan(editingNodeId).catch((error) => notify("error", error.message));
  }, [editingNodeId, authToken]);

  useEffect(() => {
    if (selectedConfigId) {
      if (selectedConfigIsManagedLink) {
        setPeer(null);
        refreshManagedLink(selectedConfigId).catch((error) => notify("error", error.message));
      } else {
        setManagedLink(null);
        refreshPeer(selectedConfigId).catch((error) => notify("error", error.message));
      }
    } else {
      setPeer(null);
      setManagedLink(null);
    }
  }, [selectedConfigId, selectedConfigIsManagedLink]);

  useEffect(() => {
    if (!managedLink?.middleware) return;
    if (managedLink.middleware.type === "udp2raw") {
      setMiddlewareType("udp2raw");
      setUdp2rawEnabled(Boolean(managedLink.middleware.enabled));
      setMimicEnabled(false);
      setUdp2rawServerSide(managedLink.middleware.server_side || "peer");
    } else if (managedLink.middleware.type === "mimic") {
      setMiddlewareType("mimic");
      setUdp2rawEnabled(false);
      setMimicEnabled(Boolean(managedLink.middleware.enabled));
    }
  }, [managedLink?.middleware]);

  useEffect(() => {
    if (!monitorDialogConfigId) return;
    refreshMonitorDetail(monitorDialogConfigId, monitorWindow).catch((error) => notify("error", error.message));
  }, [monitorDialogConfigId, monitorWindow]);

  useEffect(() => {
    if (createDialog !== "managed" || udp2rawActive || mimicActive) return;
    setManagedCreateMtu(String(replaceLocalConfig?.mtu || replacePeerConfig?.mtu || 1420));
  }, [createDialog, replaceLocalConfig?.mtu, replacePeerConfig?.mtu, udp2rawActive, mimicActive]);

  useEffect(() => {
    if (!selectedNodeId || !selectedConfigId || !selectedNodeOnline) return;
    const nodeId = selectedNodeId;
    const configId = selectedConfigId;
    let cancelled = false;
    async function refreshRuntimeStatus() {
      try {
        await api<ConfigItem>(`/api/wireguard/configs/${configId}/refresh-status`, { method: "POST" });
        if (!cancelled) {
          await refreshConfigs(nodeId, configId);
        }
      } catch (error) {
        if (!cancelled) {
          notify("error", error instanceof Error ? error.message : String(error));
        }
      }
    }
    void refreshRuntimeStatus();
    const timer = window.setInterval(() => {
      void refreshRuntimeStatus();
    }, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedNodeId, selectedConfigId, selectedNodeOnline]);

  useEffect(() => {
    if (!plan || !["confirmed", "dispatching", "running"].includes(plan.status)) return;
    const timer = window.setInterval(async () => {
      try {
        const updated = await api<ChangePlan>(`/api/change-plans/${plan.id}`);
        setPlan(updated);
        if (["succeeded", "failed", "cancelled"].includes(updated.status)) {
          notify(updated.status === "succeeded" ? "success" : "error", updated.status === "succeeded" ? "Agent 已完成部署任务。" : "Agent 任务执行失败，请查看任务结果。");
          window.clearInterval(timer);
        }
      } catch (error) {
        notify("error", error instanceof Error ? error.message : String(error));
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [plan?.id, plan?.status]);

  async function createNode(event: React.FormEvent<HTMLFormElement>) {
    // 创建节点后展示一次性 Agent token，用户需要立即保存到节点配置中。
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const controllerUrl = String(form.get("controller_url") || DEFAULT_CONTROLLER_URL).trim();
    const endpointIps = splitList(String(form.get("endpoint_ips") || ""));
    if (endpointIps.length === 0) {
      throw new Error("请至少填写一个节点入口地址");
    }
    const result = await api<NodeCreateResult>("/api/nodes", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        hostname: null,
        region: String(form.get("region") || "").trim() || null,
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
        endpoint_ips: endpointIps,
        topology_endpoint: String(form.get("topology_endpoint") || "").trim() || endpointIps[0] || null,
        github_proxy_url: null,
      }),
    });
    notify(
      "success",
      [
        `节点已创建，状态为离线。node_id=${result.node.id}`,
        `Agent token: ${result.agent_token}`,
        `主控地址: ${controllerUrl}`,
      ].join("\n"),
    );
    formElement.reset();
    setNodeCreateOpen(false);
    await refreshNodes();
    await refreshTopology();
    setSelectedNodeId(null);
  }

  async function saveNode(event: React.FormEvent<HTMLFormElement>) {
    // 修改节点名称和入口地址；入口地址用于后续受管节点互联 Endpoint 选择。
    event.preventDefault();
    if (!editingNode) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const endpointIps = splitList(String(form.get("endpoint_ips") || ""));
    if (endpointIps.length === 0) {
      throw new Error("请至少填写一个节点入口地址");
    }
    const updated = await api<NodeItem>(`/api/nodes/${editingNode.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: form.get("name"),
        endpoint_ips: endpointIps,
        hostname: editingNode.hostname,
        region: String(form.get("region") || "").trim() || null,
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
        topology_endpoint: String(form.get("topology_endpoint") || "").trim() || endpointIps[0] || null,
        github_proxy_url: String(form.get("github_proxy_url") || "").trim() || null,
      }),
    });
    setNodes((items) => items.map((item) => item.id === updated.id ? updated : item));
    await refreshTopology();
    notify("success", "节点信息已保存。");
  }

  async function rotateNodeToken() {
    // 轮换后旧 Agent token 立即失效，编辑弹窗会展示新的 token。
    if (!editingNode) return;
    const result = await api<NodeCreateResult>(`/api/nodes/${editingNode.id}/rotate-agent-token`, { method: "POST" });
    setNodes((items) => items.map((item) => item.id === result.node.id ? result.node : item));
    notify("success", "Agent token 已轮换，旧 token 已失效。");
  }

  async function deleteEditingNode() {
    if (!editingNode) return;
    const nodeConfigCount = editingNode.id === selectedNodeId ? configs.length : null;
    if (nodeConfigCount !== null && nodeConfigCount > 0) {
      throw new Error("节点下仍有 WireGuard 配置，请先删除所有配置");
    }
    if (!window.confirm(`确认删除节点 ${editingNode.name}？删除后该节点 Agent token 会失效。`)) return;
    await api<{ status: string }>(`/api/nodes/${editingNode.id}`, { method: "DELETE" });
    if (selectedNodeId === editingNode.id) {
      setSelectedNodeId(null);
      setSelectedConfigId(null);
      setConfigs([]);
      setImportCandidates([]);
      setPlan(null);
    }
    setEditingNodeId(null);
    await refreshNodes();
    notify("success", "节点已删除。");
  }

  async function copyAgentCommand() {
    if (!editingNode) return;
    const command = buildAgentCommand(editingNode, controllerUrl);
    if (!command) {
      throw new Error("当前节点没有可查看 token，请先轮换 token");
    }
    await navigator.clipboard.writeText(command);
    notify("success", "Agent 启动命令已复制。");
  }

  async function refreshAgentUpgradePlan(nodeId: number = editingNodeId || 0) {
    if (!nodeId) return;
    const data = await api<AgentUpgradePlan>(`/api/nodes/${nodeId}/agent/upgrade-plan`);
    setAgentUpgradePlan(data);
  }

  async function copyAgentUpgradeCommand() {
    if (!agentUpgradePlan?.manual_command) {
      throw new Error("当前没有可用的手动升级命令");
    }
    await navigator.clipboard.writeText(agentUpgradePlan.manual_command);
    notify("success", "Agent 升级命令已复制。");
  }

  async function requestAgentUpgrade() {
    if (!editingNode || !agentUpgradePlan) return;
    if (agentUpgradePlan.upgrade_mode !== "self_upgrade") {
      throw new Error(agentUpgradePlan.reason || "当前节点不能一键升级");
    }
    const upgradeTaskKey = nodeActionKey(editingNode.id, "agent-upgrade-task");
    holdActionPending(upgradeTaskKey);
    try {
      const result = await api<TaskRequestResult>(`/api/nodes/${editingNode.id}/agent/upgrade`, {
        method: "POST",
        body: JSON.stringify({ target_version: agentUpgradePlan.target_version, force: false }),
      });
      notify("success", result.message);
      await refreshNodes();
      await refreshAgentUpgradePlan(editingNode.id);
      if (result.task_id) {
        await pollAgentUpgradeTask(result.task_id, editingNode.id);
      }
    } finally {
      releaseActionPending(upgradeTaskKey);
    }
  }

  async function requestMimicInstall() {
    if (!editingNode) return;
    const status = mimicPluginStatus(editingNode);
    if (!status.installable) {
      throw new Error(status.detail);
    }
    const result = await api<TaskRequestResult>(`/api/nodes/${editingNode.id}/middleware/mimic/install`, {
      method: "POST",
    });
    notify("success", result.message);
    await refreshNodes();
    if (result.task_id) {
      await pollMiddlewareInstallTask(result.task_id, editingNode.id);
    }
  }

  async function pollMiddlewareInstallTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < AGENT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(TASK_POLL_INTERVAL_MS);
      const task = await api<AgentTaskStatus>(`/api/agent/tasks/${taskId}`);
      await refreshNodes();
      if (task.status === "succeeded") {
        if (task.result?.reboot_required) {
          notify("info", "mimic 已安装，但需要重启节点进入新内核后生效。");
          return;
        }
        notify("success", "mimic 安装任务完成，等待 Agent 心跳刷新能力。");
        return;
      }
      if (task.status === "failed") {
        notify("error", `mimic 安装失败：${JSON.stringify(task.result || {})}`);
        return;
      }
    }
    notify("info", "mimic 安装任务仍在进行，请稍后刷新节点状态。");
  }

  async function pollAgentUpgradeTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < AGENT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(TASK_POLL_INTERVAL_MS);
      const task = await api<AgentTaskStatus>(`/api/agent/tasks/${taskId}`);
      await refreshNodes();
      await refreshAgentUpgradePlan(nodeId);
      if (task.status === "succeeded") {
        notify("success", "Agent 升级已暂存，等待服务重启后上报新版本。");
        return;
      }
      if (task.status === "failed") {
        notify("error", `Agent 升级失败：${JSON.stringify(task.result || {})}`);
        return;
      }
    }
    notify("info", "Agent 升级任务仍在进行，请稍后刷新节点状态。");
  }

  async function saveConfig(event: React.FormEvent<HTMLFormElement>, mode: "create" | "update") {
    // 创建或修改 WireGuard 点对点配置的期望状态，不会立刻改动节点。
    event.preventDefault();
    if (!selectedNodeId) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能修改该节点的 WireGuard 配置");
    }
    const listenPort = Number(form.get("listen_port")) || null;
    const mtu = optionalInt(form.get("mtu")) ?? 1420;
    const tunnelIps = splitList(String(form.get("tunnel_ips") || ""));
    if (!isValidCidrs(tunnelIps)) {
      throw new Error("接口地址必须使用 CIDR 格式，例如 10.42.0.1/24");
    }
    if (!isValidPort(listenPort)) {
      throw new Error("监听端口必须在 1-65535 之间");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!isProbablyWireGuardKey(form.get("public_key")) || !isProbablyWireGuardKey(form.get("private_key"))) {
      throw new Error("WireGuard 密钥格式应为 44 位 base64 字符串");
    }
    const createPeerPublicKey = String(form.get("peer_public_key") || "").trim();
    const createPeerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const createPeerEndpointPort = optionalInt(form.get("peer_endpoint_port"));
    const createPeerKeepalive = optionalInt(form.get("peer_persistent_keepalive"));
    if (mode === "create") {
      const hasCreatePeerData = Boolean(
        createPeerAllowedIps.length ||
        createPeerEndpointPort ||
        createPeerKeepalive !== null ||
        String(form.get("peer_name") || "").trim() ||
        String(form.get("peer_preshared_key") || "").trim() ||
        String(form.get("peer_endpoint_host") || "").trim() ||
        String(form.get("peer_custom_config") || "").trim(),
      );
      if (hasCreatePeerData && !createPeerPublicKey) {
        throw new Error("填写 Peer 信息时必须填写对端公钥");
      }
      if (!isProbablyWireGuardKey(createPeerPublicKey)) {
        throw new Error("对端公钥格式应为 44 位 base64 字符串");
      }
      if (!isProbablyWireGuardKey(form.get("peer_preshared_key"))) {
        throw new Error("预共享密钥格式应为 44 位 base64 字符串");
      }
      if (!isValidCidrs(createPeerAllowedIps)) {
        throw new Error("AllowedIPs 必须使用 CIDR 格式，例如 172.20.0.0/14 或 fd00::/8");
      }
      if (!isValidPort(createPeerEndpointPort)) {
        throw new Error("Endpoint Port 必须留空，或填写 1-65535 之间的整数");
      }
      if (createPeerKeepalive !== null && (!Number.isInteger(createPeerKeepalive) || createPeerKeepalive < 0 || createPeerKeepalive > 65535)) {
        throw new Error("PersistentKeepalive 必须是 0-65535 之间的整数");
      }
    }
    const payload = {
      name: form.get("name"),
      tunnel_ips: tunnelIps,
      listen_port: listenPort,
      private_key: form.get("private_key") || null,
      public_key: form.get("public_key") || null,
      mtu,
      table_name: form.get("table_name") || null,
      interface_custom_config: form.get("interface_custom_config") || null,
    };
    const item = mode === "update" && selectedConfigId
      ? await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        })
      : await api<ConfigItem>(`/api/nodes/${selectedNodeId}/wireguard/configs`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
    if (mode === "create" && createPeerPublicKey) {
      await api<PeerItem>(`/api/wireguard/configs/${item.id}/peer`, {
        method: "PUT",
        body: JSON.stringify({
          name: form.get("peer_name") || null,
          public_key: createPeerPublicKey,
          preshared_key: form.get("peer_preshared_key") || null,
          endpoint_host: form.get("peer_endpoint_host") || null,
          endpoint_port: createPeerEndpointPort,
          allowed_ips: createPeerAllowedIps,
          persistent_keepalive: createPeerKeepalive,
          peer_custom_config: form.get("peer_custom_config") || null,
        }),
      });
    }
    formElement.reset();
    await refreshConfigs(selectedNodeId, item.id);
    setPlan(null);
    if (mode === "create") {
      setCreateDialog(null);
    }
    notify("success", mode === "update" ? "WireGuard 配置已保存。" : "WireGuard 配置已添加。");
  }

  async function createManagedLink(event: React.FormEvent<HTMLFormElement>) {
    // 在两个受管节点之间创建双方配置；密钥由后端调用 wg 自动生成。
    event.preventDefault();
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能创建受管节点连接");
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const peerNodeId = Number(form.get("peer_node_id"));
    const localTunnelIps = splitList(String(form.get("local_tunnel_ips") || ""));
    const peerTunnelIps = splitList(String(form.get("peer_tunnel_ips") || ""));
    const localAllowedIps = splitList(String(form.get("local_allowed_ips") || ""));
    const peerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const localEndpointHost = String(form.get("local_endpoint_host") || "").trim();
    const peerEndpointHost = String(form.get("peer_endpoint_host") || "").trim();
    const localEndpointPort = optionalInt(form.get("local_endpoint_port"));
    const peerEndpointPort = optionalInt(form.get("peer_endpoint_port"));
    const localListenPort = optionalInt(form.get("local_listen_port"));
    const peerListenPort = optionalInt(form.get("peer_listen_port"));
    const mtu = optionalInt(form.get("mtu")) ?? 1420;
    const udp2raw = middlewareType === "udp2raw" ? readUdp2RawForm(form, localListenPort, peerListenPort) : null;
    const mimic = middlewareType === "mimic" ? readMimicForm(form) : null;
    if (!peerNodeId || peerNodeId === selectedNodeId) {
      throw new Error("请选择另一个在线受管节点");
    }
    if (!isValidCidrs(localTunnelIps) || !isValidCidrs(peerTunnelIps)) {
      throw new Error("双方 IP 必须使用 CIDR 格式，例如 10.42.0.1/32");
    }
    if (!isValidCidrs(localAllowedIps) || !isValidCidrs(peerAllowedIps)) {
      throw new Error("AllowedIPs 必须使用 CIDR 格式，例如 10.42.0.2/32 或 192.168.10.0/24");
    }
    if (!isValidPort(localListenPort) || !isValidPort(peerListenPort)) {
      throw new Error("双方监听端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidPort(localEndpointPort) || !isValidPort(peerEndpointPort)) {
      throw new Error("双方 Endpoint 端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!localEndpointHost || !peerEndpointHost) {
      throw new Error("请填写双方用于互联的入口地址");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
    validateMimicForm(mimic, localListenPort, peerListenPort);
    if (replaceLocalConfigId && !replacePeerConfigId) {
      throw new Error("请选择对端的导入配置覆盖项");
    }
    const result = await api<{ local_interface: ConfigItem; peer_interface: ConfigItem }>(
      `/api/nodes/${selectedNodeId}/wireguard/managed-links`,
      {
        method: "POST",
        body: JSON.stringify({
          peer_node_id: peerNodeId,
          local_interface_name: form.get("local_interface_name"),
          peer_interface_name: form.get("peer_interface_name") || form.get("local_interface_name"),
          local_tunnel_ips: localTunnelIps,
          peer_tunnel_ips: peerTunnelIps,
          local_allowed_ips: localAllowedIps.length ? localAllowedIps : null,
          peer_allowed_ips: peerAllowedIps.length ? peerAllowedIps : null,
          local_endpoint_host: localEndpointHost,
          local_endpoint_port: localEndpointPort,
          peer_endpoint_host: peerEndpointHost,
          peer_endpoint_port: peerEndpointPort,
          local_listen_port: localListenPort,
          peer_listen_port: peerListenPort,
          mtu,
          table_name: form.get("table_name") || null,
          local_interface_custom_config: form.get("local_interface_custom_config") || null,
          local_peer_custom_config: form.get("local_peer_custom_config") || null,
          peer_interface_custom_config: form.get("peer_interface_custom_config") || null,
          peer_peer_custom_config: form.get("peer_peer_custom_config") || null,
          replace_local_interface_id: replaceLocalConfigId,
          replace_peer_interface_id: replacePeerConfigId,
          force_endpoint_mismatch: forceEndpointMismatch,
          udp2raw,
          mimic,
        }),
      },
    );
    formElement.reset();
    await refreshConfigs(selectedNodeId, result.local_interface.id);
    setPlan(null);
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setCreateDialog(null);
    [1000, 2500, 4500].forEach((delay) => {
      window.setTimeout(() => {
        void refreshConfigs(selectedNodeId, result.local_interface.id);
        void refreshManagedLink(result.local_interface.id);
      }, delay);
    });
    notify("success", `已创建 ${result.local_interface.name} / ${result.peer_interface.name}，两端部署和开机自启任务已下发。`);
  }

  async function savePeer(event: React.FormEvent<HTMLFormElement>) {
    // 设置唯一对端后仍需生成并确认 Change Plan 才会部署。
    event.preventDefault();
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能保存或部署对端配置");
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const allowedIps = splitList(String(form.get("allowed_ips") || ""));
    const endpointPort = Number(form.get("endpoint_port")) || null;
    const keepalive = Number(form.get("persistent_keepalive")) || null;
    if (!isProbablyWireGuardKey(form.get("public_key"))) {
      throw new Error("对端公钥格式应为 44 位 base64 字符串");
    }
    if (!isProbablyWireGuardKey(form.get("preshared_key"))) {
      throw new Error("预共享密钥格式应为 44 位 base64 字符串");
    }
    if (!isValidCidrs(allowedIps)) {
      throw new Error("AllowedIPs 必须使用 CIDR 格式，例如 10.42.0.2/32");
    }
    if (!isValidPort(endpointPort)) {
      throw new Error("Endpoint Port 必须在 1-65535 之间");
    }
    if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535)) {
      throw new Error("PersistentKeepalive 必须是 0-65535 之间的整数");
    }
    await api<PeerItem>(`/api/wireguard/configs/${selectedConfigId}/peer`, {
      method: "PUT",
      body: JSON.stringify({
        name: form.get("name") || null,
        public_key: form.get("public_key"),
        preshared_key: form.get("preshared_key") || null,
        endpoint_host: form.get("endpoint_host") || null,
        endpoint_port: endpointPort,
        allowed_ips: allowedIps,
        persistent_keepalive: keepalive,
        peer_custom_config: form.get("peer_custom_config") || null,
      }),
    });
    formElement.reset();
    await refreshPeer(selectedConfigId);
    if (selectedNodeId) {
      await refreshConfigs(selectedNodeId, selectedConfigId);
    }
    notify("success", "对端已保存；生成并确认部署计划后才会下发到 Agent。");
  }

  async function saveManagedLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能修改受管连接");
    }
    const form = new FormData(event.currentTarget);
    const localTunnelIps = splitList(String(form.get("local_tunnel_ips") || ""));
    const peerTunnelIps = splitList(String(form.get("peer_tunnel_ips") || ""));
    const localAllowedIps = splitList(String(form.get("local_allowed_ips") || ""));
    const peerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const localListenPort = optionalInt(form.get("local_listen_port"));
    const peerListenPort = optionalInt(form.get("peer_listen_port"));
    const localEndpointPort = optionalInt(form.get("local_endpoint_port"));
    const peerEndpointPort = optionalInt(form.get("peer_endpoint_port"));
    const keepalive = Number(form.get("persistent_keepalive")) || null;
    const mtu = optionalInt(form.get("mtu")) ?? 1420;
    const udp2raw = middlewareType === "udp2raw" ? readUdp2RawForm(form, localListenPort, peerListenPort) : null;
    const mimic = middlewareType === "mimic" ? readMimicForm(form) : null;
    if (!isValidCidrs(localTunnelIps) || !isValidCidrs(peerTunnelIps)) {
      throw new Error("双方 IP 必须使用 CIDR 格式，例如 10.42.0.1/32, fd42::1/64");
    }
    if (!isValidCidrs(localAllowedIps) || !isValidCidrs(peerAllowedIps)) {
      throw new Error("AllowedIPs 必须使用 CIDR 格式，例如 10.42.0.2/32 或 192.168.10.0/24");
    }
    if (!isValidPort(localListenPort) || !isValidPort(peerListenPort)) {
      throw new Error("双方监听端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidPort(localEndpointPort) || !isValidPort(peerEndpointPort)) {
      throw new Error("双方 Endpoint 端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535)) {
      throw new Error("PersistentKeepalive 必须是 0-65535 之间的整数");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
    validateMimicForm(mimic, localListenPort, peerListenPort);
    await api<ManagedLink>(`/api/wireguard/configs/${selectedConfigId}/managed-link`, {
      method: "PATCH",
      body: JSON.stringify({
        local_interface_name: form.get("local_interface_name"),
        peer_interface_name: form.get("peer_interface_name"),
        local_tunnel_ips: localTunnelIps,
        peer_tunnel_ips: peerTunnelIps,
        local_allowed_ips: localAllowedIps.length ? localAllowedIps : null,
        peer_allowed_ips: peerAllowedIps.length ? peerAllowedIps : null,
        local_endpoint_host: String(form.get("local_endpoint_host") || "").trim(),
        local_endpoint_port: localEndpointPort,
        peer_endpoint_host: String(form.get("peer_endpoint_host") || "").trim(),
        peer_endpoint_port: peerEndpointPort,
        local_listen_port: localListenPort,
        peer_listen_port: peerListenPort,
        mtu,
        table_name: form.get("table_name") || null,
        persistent_keepalive: keepalive,
        local_interface_custom_config: form.get("local_interface_custom_config") || null,
        local_peer_custom_config: form.get("local_peer_custom_config") || null,
        peer_interface_custom_config: form.get("peer_interface_custom_config") || null,
        peer_peer_custom_config: form.get("peer_peer_custom_config") || null,
        udp2raw,
        mimic,
      }),
    });
    await refreshConfigs(selectedNodeId, selectedConfigId);
    [1000, 2500, 4500].forEach((delay) => {
      window.setTimeout(() => {
        void refreshConfigs(selectedNodeId, selectedConfigId);
        void refreshManagedLink(selectedConfigId);
      }, delay);
    });
    notify("success", "受管连接已保存，并已直接下发双方配置。");
  }

  async function createApplyPlan() {
    // 生成部署计划，前端必须展示 diff 并由用户确认后才会创建 Agent 任务。
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能生成部署计划");
    }
    const data = await api<ChangePlan>(`/api/wireguard/configs/${selectedConfigId}/plan-apply`, {
      method: "POST",
    });
    setPlan(data);
    if (!data.diff.trim()) {
      notify("info", selectedConfig?.source === "imported" && !selectedConfig.managed
        ? "导入配置已使用节点现有 wg-quick 文件作为基线，无需重新下发。"
        : "当前配置与已部署配置一致，无需下发。");
    }
  }

  async function refreshDeployedConfig() {
    // 请求 Agent 读取节点上的当前配置，下一次部署计划会以此作为 diff 基线。
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能同步节点配置");
    }
    await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/refresh-deployed`, { method: "POST" });
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", "已创建同步任务；稍后再次生成部署计划会使用节点当前配置作为基线。");
  }

  async function startSelectedConfig() {
    // 启动已部署的 WireGuard 接口。
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能启动 WireGuard 连接");
    }
    if (selectedConfigIsManagedLink) {
      await api<ManagedLink>(`/api/wireguard/configs/${selectedConfigId}/managed-link/start`, { method: "POST" });
    } else {
      await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/start`, { method: "POST" });
    }
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", selectedConfigIsManagedLink ? "已创建双方启动任务，等待 Agent 执行。" : isConfigRunning ? "WireGuard 连接已经是已连接状态。" : "启动任务已创建，等待 Agent 执行。");
  }

  async function stopSelectedConfig() {
    // 断开 WireGuard 接口；删除配置前必须先完成这一步。
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能断开 WireGuard 连接");
    }
    if (selectedConfigIsManagedLink) {
      await api<ManagedLink>(`/api/wireguard/configs/${selectedConfigId}/managed-link/stop`, { method: "POST" });
    } else {
      await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/stop`, { method: "POST" });
    }
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", selectedConfigIsManagedLink ? "已创建双方断开任务，等待 Agent 执行。" : isConfigStopped ? "WireGuard 连接已经是已断开状态。" : "断开任务已创建，等待 Agent 执行。");
  }

  async function openDeleteDialog() {
    if (!selectedConfigId || !selectedNodeId || !selectedConfig) return;
    if (!selectedConfigIsUnmanagedImport && !selectedNodeOnline) {
      throw new Error("Agent 离线，不能删除 WireGuard 配置");
    }
    if (!selectedConfigIsUnmanagedImport && !isConfigStopped) {
      throw new Error("删除前必须先断开对应 WireGuard 连接");
    }
    setDeleteNodeConfig(false);
    setDeleteDialogOpen(true);
  }

  async function deleteSelectedConfig() {
    // 默认只删除 Link42 记录；用户勾选后才同步删除节点配置和服务。
    if (!selectedConfigId || !selectedNodeId || !selectedConfig) return;
    const query = deleteNodeConfig ? "?delete_node_config=true" : "";
    if (selectedConfigIsManagedLink) {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}/managed-link${query}`, { method: "DELETE" });
    } else {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}${query}`, { method: "DELETE" });
    }
    setDeleteDialogOpen(false);
    setDeleteNodeConfig(false);
    setSelectedConfigId(null);
    setPlan(null);
    await refreshConfigs(selectedNodeId, null);
    await refreshImportCandidates(selectedNodeId);
    notify("success", selectedConfigIsManagedLink
      ? (deleteNodeConfig ? "受管连接双方记录已删除，并已下发节点配置清理任务。" : "受管连接双方记录已删除，节点配置已保留。")
      : selectedConfigIsUnmanagedImport
        ? "导入观察记录已删除，节点原始配置文件未改动。"
        : (deleteNodeConfig ? "WireGuard 记录已删除，并已下发节点配置清理任务。" : "WireGuard 记录已删除，节点配置已保留。"));
  }

  async function confirmPlan() {
    // 确认计划会创建 Agent 任务；这是第一版的关键安全闸门。
    if (!plan) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能确认部署计划");
    }
    if (!hasDeployDiff) {
      throw new Error("当前计划没有 diff，无需下发任务");
    }
    const data = await api<ChangePlan>(`/api/change-plans/${plan.id}/confirm`, { method: "POST" });
    setPlan(data);
    notify("success", "部署任务已创建，等待 Agent 拉取执行。");
  }

  async function requestImportScan() {
    // 请求 Agent 扫描现有 wg-quick 配置；扫描不需要用户审 diff，直接创建任务。
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能扫描节点配置");
    }
    const data = await api<TaskRequestResult>(`/api/nodes/${selectedNodeId}/wireguard/import-scan`, {
      method: "POST",
    });
    notify(
      "success",
      data.status === "pending" ? "扫描任务已创建，等待 Agent 执行。" : "扫描任务已在执行，正在等待结果。",
    );
    await refreshNodes();
    await refreshConfigs(selectedNodeId, selectedConfigId);
    await refreshImportCandidates(selectedNodeId);
    setImportCandidatesExpanded(true);
    if (data.task_id) {
      await pollImportScanTask(data.task_id, selectedNodeId);
    }
  }

  async function pollImportScanTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < SHORT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(1000);
      const task = await api<AgentTaskStatus>(`/api/agent/tasks/${taskId}`);
      await refreshNodes();
      await refreshConfigs(nodeId, selectedConfigId);
      await refreshImportCandidates(nodeId);
      if (task.status === "succeeded") {
        notify("success", "扫描完成，已刷新现有 wg-quick 候选和节点配置。");
        return;
      }
      if (task.status === "failed") {
        notify("error", `扫描失败：${JSON.stringify(task.result || {})}`);
        return;
      }
    }
    notify("info", "扫描任务仍在执行，页面已刷新；稍后可再次查看。");
  }

  async function importCandidate(candidateId: number) {
    // 导入候选只会写入数据库，默认仍是 unmanaged，不会覆盖节点配置。
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能导入节点配置");
    }
    const item = await api<ConfigItem>(`/api/nodes/${selectedNodeId}/wireguard/import`, {
      method: "POST",
      body: JSON.stringify({ candidate_id: candidateId }),
    });
    notify("success", `已导入 ${item.name}，当前仍未接管管理。`);
    await refreshConfigs(selectedNodeId);
    await refreshImportCandidates(selectedNodeId);
    setSelectedConfigId(item.id);
  }

  async function takeOverConfig() {
    // 接管导入接口会生成计划；只有确认计划后才会备份并写入节点配置。
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能接管配置");
    }
    const data = await api<ChangePlan>(`/api/wireguard/configs/${selectedConfigId}/take-over`, {
      method: "POST",
    });
    setPlan(data);
    if (selectedNodeId) {
      await refreshConfigs(selectedNodeId, selectedConfigId);
    }
    if (!data.diff.trim()) {
      notify("success", "已接管现有 wg-quick 配置，未重写节点文件。");
    }
  }

  if (!authChecked) {
    return <main className="app loginPage" />;
  }

  if (!authToken) {
    return (
      <main className="app loginPage">
        <section className="loginPanel">
          <div className="loginBrand">
            <img src={siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
            <h1>{siteTitle || DEFAULT_SITE_TITLE}</h1>
          </div>
          <p className="muted">主控访问登录</p>
          <form className="stack" onSubmit={(event) => void runAction(() => login(event), "auth:login")}>
            <Field label="用户名">
              <input name="username" defaultValue={settingsUsername} autoComplete="username" required onChange={() => setLoginError("")} />
            </Field>
            <Field label="密码">
              <input name="password" type="password" autoComplete="current-password" required onChange={() => setLoginError("")} />
            </Field>
            {loginError && <div className="formError" role="alert">{loginError}</div>}
            <button type="submit" disabled={actionPending("auth:login")}><Check size={16} /> {actionPending("auth:login") ? "登录中" : "登录"}</button>
          </form>
        </section>
        <div className="toastStack" aria-live="polite">
          {toasts.map((toast) => (
            <div key={toast.id} className={`toast ${toast.type}`}>
              {toast.text}
            </div>
          ))}
        </div>
      </main>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <div className="brandBlock">
          <img className="brandLogo" src={siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
          <div>
            <h1>{siteTitle || DEFAULT_SITE_TITLE}</h1>
            <p>WireGuard 点对点链路管理面板 / {currentUser || "pmman"}</p>
          </div>
        </div>
        <div className="topbarActions">
          <button className="iconButton" onClick={() => setSettingsOpen(true)} title="设置">
            <Settings size={18} />
          </button>
          <button className="iconButton" onClick={() => void runAction(refreshHome)} title="刷新">
            <RefreshCw size={18} />
          </button>
          <button className="iconButton" onClick={() => void runAction(logout)} title="退出">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <div className="toastStack" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.type}`}>
            {toast.text}
          </div>
        ))}
      </div>

      {settingsOpen && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
            <header className="modalHeader">
              <div>
                <h2 id="settings-title"><Settings size={18} /> 系统设置</h2>
                <p className="muted">主控访问地址用于生成 Agent 安装命令；账号用于登录面板。</p>
              </div>
              <button className="iconButton" onClick={() => setSettingsOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <form className="stack" onSubmit={(event) => void runAction(() => saveSettings(event), "settings:save")}>
              <Field label="主控访问地址" hint="Agent 节点能访问到的 URL，例如 http://192.168.123.20:8000。">
                <input name="controller_url" defaultValue={controllerUrl} placeholder={DEFAULT_CONTROLLER_URL} required />
              </Field>
              <Field label="用户名">
                <input name="username" defaultValue={settingsUsername} required />
              </Field>
              <Field label="站点标题" hint="展示在浏览器标题、登录页和顶部栏。">
                <input name="site_title" defaultValue={siteTitle} required />
              </Field>
              <Field label="Logo" hint="上传 PNG、JPEG 或 WebP；文件会保存到主控配置目录，Docker 映射后可持久化。">
                <div className="logoUploadField">
                  <img src={settingsLogoPreviewUrl || siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
                  <input name="site_logo_file" type="file" accept="image/png,image/jpeg,image/webp" onChange={previewLogoFile} />
                </div>
              </Field>
              <Field label="新密码" hint="留空表示不修改密码。">
                <input name="new_password" type="password" autoComplete="new-password" minLength={6} />
              </Field>
              <button type="submit" disabled={actionPending("settings:save")}><Check size={16} /> {actionPending("settings:save") ? "保存中" : "保存设置"}</button>
            </form>
          </section>
        </div>
      )}

      {nodeCreateOpen && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="node-create-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-create-title"><Server size={18} /> 添加节点</h2>
                <p className="muted">入口地址会用于受管节点之间互联时选择 Endpoint。</p>
              </div>
              <button className="iconButton" onClick={() => setNodeCreateOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <form onSubmit={(event) => void runAction(() => createNode(event), "node:create")} className="gridForm">
              <Field label="节点名称" hint="用于在控制台识别这个 Agent。">
                <input name="name" placeholder="node-a" required />
              </Field>
              <Field label="主控地址" hint="Agent 安装时连接的 Link42 API 地址。">
                <input name="controller_url" placeholder="http://192.168.123.20:8000" defaultValue={controllerUrl} required />
              </Field>
              <Field label="入口地址" hint="多个地址用逗号分隔，后续受管连接会从这里选择 Endpoint。" wide>
                <textarea name="endpoint_ips" placeholder="203.0.113.10, 10.0.0.10" required />
              </Field>
              <Field label="节点地域" hint="拓扑图展示的地域，例如 广州 / 东京 / HomeLab。">
                <input name="region" placeholder="广州" />
              </Field>
              <Field label="拓扑展示地址" hint="拓扑图展示的本机地址；留空使用第一个入口地址。">
                <input name="topology_endpoint" placeholder="10.10.0.1" />
              </Field>
              <button type="submit" disabled={actionPending("node:create")}><Plus size={16} /> {actionPending("node:create") ? "创建中" : "创建节点"}</button>
            </form>
          </section>
        </div>
      )}

      {editingNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="node-edit-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-edit-title"><Server size={18} /> 节点设置</h2>
                <p className="muted">node_id={editingNode.id} / {editingNode.status}</p>
              </div>
              <button className="iconButton" onClick={() => setEditingNodeId(null)}>
                <X size={18} />
              </button>
            </header>
            <form key={`node-edit-${editingNode.id}`} onSubmit={(event) => void runAction(() => saveNode(event), nodeActionKey(editingNode.id, "save"))} className="gridForm">
              <Field label="节点名称" hint="修改后会同步显示在节点列表。">
                <input name="name" placeholder="node-a" defaultValue={editingNode.name} required />
              </Field>
              <Field label="节点地域" hint="拓扑图展示的地域，例如 广州 / 东京 / HomeLab。">
                <input name="region" placeholder="广州" defaultValue={editingNode.region || ""} />
              </Field>
              <Field label="入口地址" hint="多个地址用逗号分隔；受管连接会校验所选地址属于节点。" wide>
                <textarea name="endpoint_ips" placeholder="203.0.113.10, 10.0.0.10" defaultValue={nodeEndpointOptions(editingNode).join(", ")} required />
              </Field>
              <Field label="拓扑展示地址" hint="选择或输入拓扑节点卡片展示的本机地址；留空使用第一个入口地址。" wide>
                <EndpointSelect
                  name="topology_endpoint"
                  options={endpointOptionsFrom(null, nodeEndpointOptions(editingNode), editingNode.topology_endpoint)}
                  defaultValue={editingNode.topology_endpoint || ""}
                  placeholder="选择或输入展示地址"
                />
              </Field>
              <Field label="GitHub 代理 URL" hint="Agent 安装 GitHub release 插件时使用；留空则直连 GitHub。" wide>
                <input name="github_proxy_url" placeholder="https://gh-proxy.example.com/" defaultValue={editingNode.github_proxy_url || ""} />
              </Field>
              <button type="submit" disabled={actionPending(nodeActionKey(editingNode.id, "save"))}><Check size={16} /> {actionPending(nodeActionKey(editingNode.id, "save")) ? "保存中" : "保存节点"}</button>
            </form>
            <section className="modalSection">
              <h3>中间层插件</h3>
              <div className="pluginStatus">
                <div>
                  <strong>mimic</strong>
                  <p className="muted">{editingNodeMimicStatus.detail}</p>
                  <small>状态：{editingNodeMimicStatus.label} / 来源：GitHub latest release</small>
                </div>
                <button
                  className="secondary"
                  disabled={!editingNodeMimicStatus.installable || actionPending(nodeActionKey(editingNode.id, "mimic-install"))}
                  onClick={() => void runAction(requestMimicInstall, nodeActionKey(editingNode.id, "mimic-install"))}
                >
                  <Upload size={16} /> {editingNodeMimicStatus.rebootRequired ? "需要重启后生效" : actionPending(nodeActionKey(editingNode.id, "mimic-install")) ? "安装中" : "安装 latest"}
                </button>
              </div>
            </section>
            <section className="modalSection">
              <h3>Agent token</h3>
              {editingNode.agent_token_value ? (
                <pre className="tokenBox">{editingNode.agent_token_value}</pre>
              ) : (
                <div className="empty">该节点创建时未保存明文 token，请轮换后查看。</div>
              )}
              <div className="empty">
                Agent {editingNode.agent_version || "未知版本"} / {nodeSystemLabel(editingNode)}
                <br />
                {(editingNode.agent_capabilities || []).join(", ") || "尚未上报能力"}
              </div>
              <pre className="tokenBox">{buildAgentCommand(editingNode, controllerUrl) || "轮换 token 后显示 Agent 启动命令。"}</pre>
              <div className="actionRow">
                <button className="secondary" onClick={() => void runAction(copyAgentCommand)}>复制启动命令</button>
                <button className="danger" disabled={actionPending(nodeActionKey(editingNode.id, "rotate-token"))} onClick={() => void runAction(rotateNodeToken, nodeActionKey(editingNode.id, "rotate-token"))}>轮换 token</button>
              </div>
            </section>
            <section className="modalSection">
              <h3>Agent 升级</h3>
              {agentUpgradePlan ? (
                <>
                  <div className="empty">
                    当前版本：{agentUpgradePlan.current_version || editingNode.agent_version || "未知"}
                    <br />
                    目标版本：{agentUpgradePlan.target_version || "无可用版本"}
                    <br />
                    升级状态：{agentUpgradePlan.status || editingNode.agent_update_status || "未开始"}
                    {agentUpgradePlan.matched_platform && (
                      <>
                        <br />
                        匹配资产：{agentUpgradePlan.matched_platform}
                      </>
                    )}
                    {agentUpgradePlan.reason && (
                      <>
                        <br />
                        {agentUpgradePlan.reason}
                      </>
                    )}
                  </div>
                  <div className="actionRow">
                    <button
                      className="secondary"
                      disabled={actionPending(nodeActionKey(editingNode.id, "refresh-upgrade-plan"))}
                      onClick={() => void runAction(() => refreshAgentUpgradePlan(editingNode.id), nodeActionKey(editingNode.id, "refresh-upgrade-plan"))}
                    >
                      <RefreshCw size={16} /> {actionPending(nodeActionKey(editingNode.id, "refresh-upgrade-plan")) ? "刷新中" : "刷新升级计划"}
                    </button>
                    {agentUpgradePlan.upgrade_mode === "self_upgrade" ? (
                      <button
                        disabled={actionPending(nodeActionKey(editingNode.id, "agent-upgrade")) || actionPending(nodeActionKey(editingNode.id, "agent-upgrade-task"))}
                        onClick={() => void runAction(requestAgentUpgrade, nodeActionKey(editingNode.id, "agent-upgrade"))}
                      >
                        <Upload size={16} /> {actionPending(nodeActionKey(editingNode.id, "agent-upgrade")) || actionPending(nodeActionKey(editingNode.id, "agent-upgrade-task")) ? "升级中" : "一键升级"}
                      </button>
                    ) : (
                      <button className="secondary" disabled={!agentUpgradePlan.manual_command} onClick={() => void runAction(copyAgentUpgradeCommand)}>
                        复制升级命令
                      </button>
                    )}
                  </div>
                  {agentUpgradePlan.manual_command && (
                    <pre className="tokenBox">{agentUpgradePlan.manual_command}</pre>
                  )}
                  {editingNode.agent_last_error && <div className="empty">上次错误：{editingNode.agent_last_error}</div>}
                </>
              ) : (
                <div className="empty">正在读取 Agent 升级计划。</div>
              )}
            </section>
            <section className="modalSection dangerZone">
              <h3>删除节点</h3>
              <p className="muted">只有节点下所有 WireGuard 配置都已删除时，才允许删除节点。</p>
              <button className="danger" disabled={actionPending(nodeActionKey(editingNode.id, "delete"))} onClick={() => void runAction(deleteEditingNode, nodeActionKey(editingNode.id, "delete"))}>
                删除节点
              </button>
            </section>
          </section>
        </div>
      )}

      {createDialog === "external" && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="manual-link-title">
            <header className="modalHeader">
              <div>
                <h2 id="manual-link-title"><Plus size={18} /> 手动创建连接</h2>
                <p className="muted">{selectedNode.name} 连接到非受管节点。可在创建时直接填写 Peer，随后生成部署计划。</p>
              </div>
              <button className="iconButton" onClick={() => setCreateDialog(null)}>
                <X size={18} />
              </button>
            </header>
            <form
              key={`create-config-modal-${selectedNode.id}`}
              onSubmit={(event) => void runAction(() => saveConfig(event, "create"), nodeActionKey(selectedNode.id, "create-config"))}
              className="gridForm describedForm"
            >
              <Field label="接口名称" hint="节点上的 wg-quick 接口名，例如 wg0。">
                <input name="name" placeholder="wg0" required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端隧道地址" hint="CIDR 格式，多个地址用逗号分隔。">
                <input name="tunnel_ips" placeholder="10.42.0.1/24" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="监听端口" hint="UDP 端口，留空表示不写 ListenPort。">
                <input name="listen_port" placeholder="51820" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="MTU" hint="链路 MTU，默认 1420。">
                <input name="mtu" placeholder="1420" defaultValue="1420" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                <RouteModeSelect disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端公钥" hint="可选；用于记录和展示，44 位 base64。">
                <input name="public_key" placeholder="base64 public key" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端私钥" hint="可选；可信面板会明文保存并渲染到本机配置。" wide>
                <textarea name="private_key" placeholder="base64 private key" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="Interface 高级配置" hint="逐行写入 [Interface] 后，例如 PostUp/PostDown。不会做语义校验。" wide>
                <textarea name="interface_custom_config" placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端名称" hint="可选，仅用于界面识别。">
                <input name="peer_name" placeholder="remote-site" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端公钥" hint="可选；填写后会同时创建唯一 Peer。">
                <input name="peer_public_key" placeholder="base64 public key" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="AllowedIPs" hint="写入 [Peer]，dn42 常见为 172.20.0.0/14, fd00::/8。">
                <input name="peer_allowed_ips" placeholder="172.20.0.0/14, fd00::/8" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="Endpoint Host" hint="对端公网 IP、内网 IP 或域名；可留空。">
                <input name="peer_endpoint_host" placeholder="203.0.113.20" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="Endpoint Port" hint="对端 UDP 端口；Host 留空时通常也留空。">
                <input name="peer_endpoint_port" placeholder="51820" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="PersistentKeepalive" hint="NAT 后常用 25；留空表示不写。">
                <input name="peer_persistent_keepalive" placeholder="25" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="预共享密钥" hint="可选，填写后会渲染 PresharedKey。">
                <input name="peer_preshared_key" placeholder="base64 preshared key" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="Peer 高级配置" hint="逐行写入 [Peer] 后，例如自定义标记行。不会做语义校验。" wide>
                <textarea name="peer_custom_config" placeholder="自定义 Peer 行" disabled={!selectedNodeOnline} />
              </Field>
	              <button type="submit" disabled={!selectedNodeOnline || actionPending(nodeActionKey(selectedNode.id, "create-config"))}><Plus size={16} /> {actionPending(nodeActionKey(selectedNode.id, "create-config")) ? "添加中" : "添加配置"}</button>
            </form>
          </section>
        </div>
      )}

      {createDialog === "managed" && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel" role="dialog" aria-modal="true" aria-labelledby="managed-link-title">
            <header className="modalHeader">
              <div>
                <h2 id="managed-link-title"><GitBranch size={18} /> 创建受管连接</h2>
                <p className="muted">系统会为双方生成密钥，部署并启动连接，同时启用对应节点的服务或开机配置。</p>
              </div>
              <button
                className="iconButton"
                onClick={closeCreateDialog}
              >
                <X size={18} />
              </button>
            </header>
            <form
              key={`create-managed-link-modal-${selectedNode.id}`}
              onSubmit={(event) => void runAction(() => createManagedLink(event), nodeActionKey(selectedNode.id, "create-managed-link"))}
              className="gridForm describedForm"
            >
              <FormSection title="节点与导入" hint="选择对端节点；需要接管现有 wg-quick 配置时，在这里指定双方要替换的导入配置。">
              <Field label="对端节点" hint="只能选择当前在线的其它受管节点。">
                <select
                  name="peer_node_id"
                  required
                  disabled={!selectedNodeOnline}
                  onChange={(event) => {
                    setManagedPeerNodeId(Number(event.currentTarget.value) || null);
                    setReplacePeerConfigId(null);
                  }}
                >
                  <option value="">选择节点</option>
                  {selectedPeerNodeOptions.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              <Field label="替换本端导入配置" hint="可选；用于把现有 wg-quick 配置替换为新的受管连接。">
                <select
                  value={replaceLocalConfigId || ""}
                  disabled={!selectedNodeOnline}
                  onChange={(event) => setReplaceLocalConfigId(Number(event.currentTarget.value) || null)}
                >
                  <option value="">不替换</option>
                  {configs.filter((item) => item.source === "imported" && !item.managed).map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              <Field
                label="替换对端导入配置"
                hint={replaceLocalConfigId ? "必选；本端导入配置转受管时必须指定对端要覆盖的导入配置。" : "可选；选择后创建时会停用并删除旧配置文件。"}
              >
                <select
                  value={replacePeerConfigId || ""}
                  required={Boolean(replaceLocalConfigId)}
                  disabled={!selectedNodeOnline || !managedPeerNodeId}
                  onChange={(event) => setReplacePeerConfigId(Number(event.currentTarget.value) || null)}
                >
                  <option value="">不替换</option>
                  {replacePeerConfigOptions.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              </FormSection>
              <FormSection title="接口与隧道地址" hint="接口名写入双方节点；隧道 IP 和 AllowedIPs 支持多个 CIDR，用逗号分隔。">
              <Field label="本端接口名称" hint="当前节点上创建的接口名。">
                <input name="local_interface_name" placeholder="wg-node-a" defaultValue={replaceLocalConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端接口名称" hint="对端节点上创建的接口名；同机双 Agent 测试时必须不同。">
                <input name="peer_interface_name" placeholder="wg-node-b" defaultValue={replacePeerConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端隧道 IP" hint="本端 WireGuard Address；例如 10.42.0.1/32, fd42::1/64。">
                <input name="local_tunnel_ips" placeholder="10.42.0.1/32, fd42::1/64" defaultValue={replaceLocalConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端隧道 IP" hint="对端 WireGuard Address；例如 10.42.0.2/32, fd42::2/64。">
                <input name="peer_tunnel_ips" placeholder="10.42.0.2/32, fd42::2/64" defaultValue={replacePeerConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端监听端口" hint="可选；留空表示本端 WireGuard 不写 ListenPort。udp2raw server 在本端时必须填写。">
                <input name="local_listen_port" placeholder="51820" defaultValue={replaceLocalConfig?.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端监听端口" hint="可选；留空表示对端 WireGuard 不写 ListenPort。udp2raw server 在对端时必须填写。">
                <input name="peer_listen_port" placeholder="51821" defaultValue={replacePeerConfig?.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              <FormSection title="直连入口与路由" hint="直连和 mimic 使用这里的真实 Endpoint；只有 udp2raw 会把 Endpoint 接管到本地 client。">
              <Field label="本端入口地址" hint="对端连接本节点时使用的 Endpoint 地址。">
                <EndpointSelect
                  key={`managed-local-endpoint-${replacePeerConfigId || "none"}-${managedLocalEndpointDefault}`}
                  name="local_endpoint_host"
                  defaultValue={managedLocalEndpointDefault}
                  placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                  options={managedLocalEndpointOptions}
                  disabled={!selectedNodeOnline}
                  locked={udp2rawActive}
                />
              </Field>
              <Field label="本端 Endpoint 端口" hint="对端直连本节点时使用；留空则使用本端 ListenPort。udp2raw 启用时由中间层接管。">
                <input
                  name="local_endpoint_port"
                  placeholder="51820"
                  defaultValue={replaceLocalConfig?.listen_port || ""}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline || udp2rawActive}
                />
              </Field>
              <Field label="对端入口地址" hint="本端连接对端节点时使用的 Endpoint 地址。">
                <EndpointSelect
                  key={`managed-peer-endpoint-${replaceLocalConfigId || "none"}-${managedPeerEndpointDefault}`}
                  name="peer_endpoint_host"
                  defaultValue={managedPeerEndpointDefault}
                  placeholder={selectedPeerEndpoints[0] || "203.0.113.20"}
                  options={managedPeerEndpointOptions}
                  disabled={!selectedNodeOnline}
                  locked={udp2rawActive}
                />
              </Field>
              <Field label="对端 Endpoint 端口" hint="本端直连对端节点时使用；留空则使用对端 ListenPort。udp2raw 启用时由中间层接管。">
                <input
                  name="peer_endpoint_port"
                  placeholder="51821"
                  defaultValue={replacePeerConfig?.listen_port || ""}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline || udp2rawActive}
                />
              </Field>
              <Field label="本端 Peer AllowedIPs" hint="写入当前节点 [Peer]；留空则使用对端隧道 IP。">
                <input
                  key={`managed-local-allowed-${replaceLocalConfigId || "none"}-${replacePeerConfigId || "none"}-${managedLocalAllowedIpsDefault}`}
                  name="local_allowed_ips"
                  placeholder="10.42.0.2/32, 192.168.20.0/24"
                  defaultValue={managedLocalAllowedIpsDefault}
                  disabled={!selectedNodeOnline}
                />
              </Field>
              <Field label="对端 Peer AllowedIPs" hint="写入对端节点 [Peer]；留空则使用本端隧道 IP。">
                <input
                  key={`managed-peer-allowed-${replaceLocalConfigId || "none"}-${replacePeerConfigId || "none"}-${managedPeerAllowedIpsDefault}`}
                  name="peer_allowed_ips"
                  placeholder="10.42.0.1/32, 192.168.10.0/24"
                  defaultValue={managedPeerAllowedIpsDefault}
                  disabled={!selectedNodeOnline}
                />
              </Field>
              </FormSection>
              <FormSection title="连接中间层" hint="udp2raw 通过本地代理接管 Endpoint；mimic 在网卡层透明处理真实 Endpoint 流量。">
                <Field label="中间层类型" hint="OpenWrt 当前只支持 udp2raw；mimic 需要非 OpenWrt Linux kernel > 6.1 且已安装 mimic。">
                  <select
                    value={middlewareType}
                    disabled={!selectedNodeOnline}
                    onChange={(event) => {
                      const next = event.currentTarget.value as "none" | "udp2raw" | "mimic";
                      setMiddlewareType(next);
                      setUdp2rawEnabled(next === "udp2raw");
                      setMimicEnabled(next === "mimic");
                      if (next === "udp2raw") setManagedCreateMtu("1300");
                      if (next === "mimic") setManagedCreateMtu("1408");
                    }}
                  >
                    <option value="none">不使用中间层</option>
                    <option value="udp2raw">udp2raw</option>
                    <option value="mimic">mimic</option>
                  </select>
                </Field>
              </FormSection>
              {middlewareType === "udp2raw" && (
                <Udp2RawFields
                  enabled={udp2rawEnabled}
                  serverSide={udp2rawServerSide}
                  localListenPort={replaceLocalConfig?.listen_port}
                  peerListenPort={replacePeerConfig?.listen_port}
                  disabled={!selectedNodeOnline}
                  onEnabledChange={(enabled) => {
                    setUdp2rawEnabled(enabled);
                    if (enabled) setManagedCreateMtu("1300");
                  }}
                  onServerSideChange={setUdp2rawServerSide}
                />
              )}
              {middlewareType === "mimic" && (
                <MimicFields
                  enabled={mimicEnabled}
                  localNode={selectedNode}
                  peerNode={selectedManagedPeerNode}
                  disabled={!selectedNodeOnline}
                  onEnabledChange={(enabled) => {
                    setMimicEnabled(enabled);
                    if (enabled) setManagedCreateMtu("1408");
                  }}
                />
              )}
              <FormSection title="链路参数" hint="Table=off 是 DN42 常用默认值；启用中间层时 MTU 默认降到 1300，但仍可手动调整。">
              <Field label="MTU" hint={udp2rawActive ? "启用 udp2raw 时建议降低 MTU；已自动填入 1300，可手动修改。" : mimicActive ? "启用 mimic 时建议将 IPv6 WireGuard MTU 降到 1408，可手动修改。" : "双方链路 MTU，默认 1420。"}>
                <input
                  name="mtu"
                  placeholder="1420"
                  value={managedCreateMtu}
                  onChange={(event) => setManagedCreateMtu(event.currentTarget.value)}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline}
                />
              </Field>
              <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                <RouteModeSelect defaultValue={replaceLocalConfig?.table_name || replacePeerConfig?.table_name || "off"} disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              <FormSection title="高级配置" hint="这些内容会原样追加到对应的 [Interface] 或 [Peer] 区块，请只填写 WireGuard 支持的配置行。">
              <Field label="本端 Interface 高级配置" hint="写入当前节点 [Interface] 后，例如 PostUp。不同节点可不同。" wide>
                <textarea name="local_interface_custom_config" defaultValue={replaceLocalConfig?.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端 Peer 高级配置" hint="写入当前节点 [Peer] 后。" wide>
                <textarea name="local_peer_custom_config" placeholder="AllowedIPs 之外的自定义 Peer 行" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端 Interface 高级配置" hint="写入对端节点 [Interface] 后，例如不同的 PostUp。" wide>
                <textarea name="peer_interface_custom_config" defaultValue={replacePeerConfig?.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端 Peer 高级配置" hint="写入对端节点 [Peer] 后。" wide>
                <textarea name="peer_peer_custom_config" placeholder="AllowedIPs 之外的自定义 Peer 行" disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              {(replaceLocalConfigId || replacePeerConfigId) && (
                <label className="checkField wideField">
                  <input
                    type="checkbox"
                    checked={forceEndpointMismatch}
                    onChange={(event) => setForceEndpointMismatch(event.currentTarget.checked)}
                  />
                  <span>如果旧配置 Endpoint 与所选节点地址不匹配，仍强制替换</span>
                </label>
              )}
              <button
                type="submit"
                disabled={
                  !selectedNodeOnline ||
                  selectedPeerNodeOptions.length === 0 ||
                  Boolean(replaceLocalConfigId && !replacePeerConfigId) ||
                  actionPending(nodeActionKey(selectedNode.id, "create-managed-link"))
                }
              >
                <GitBranch size={16} /> {actionPending(nodeActionKey(selectedNode.id, "create-managed-link")) ? "创建中" : "创建并启动双方连接"}
              </button>
            </form>
          </section>
        </div>
      )}

      <section className="nodeBoard">
        <section className="nodeCreate">
          <div>
            <h2><Server size={18} /> 节点</h2>
            <p className="muted">先创建节点并填写可被其它节点访问的入口地址。</p>
          </div>
          <button type="button" onClick={() => setNodeCreateOpen(true)}><Plus size={16} /> 添加节点</button>
        </section>

        <section className="topologyPanel">
          <header className="topologyHeader">
            <div>
              <h2><GitBranch size={18} /> 拓扑图</h2>
              <p className="muted">根据受管节点连接自动生成；拖动节点可保存自定义位置。</p>
            </div>
            <div className="topologyToolbar">
              <span className="topologyMeta">{topology.nodes.length} 个节点 / {topology.edges.length} 条链路</span>
              <button
                className="secondary"
                type="button"
                disabled={actionPending("topology:reset")}
                onClick={() => void runAction(resetTopologyLayout, "topology:reset")}
              >
                <RefreshCw size={16} /> {actionPending("topology:reset") ? "还原中" : "还原拓扑"}
              </button>
            </div>
          </header>
          <div className="topologyCanvas">
            {topology.nodes.length === 0 ? (
              <div className="empty">创建节点和受管连接后会显示拓扑。</div>
            ) : (
              <ReactFlow
                nodes={topologyFlowNodes}
                edges={topologyFlowEdges}
                fitView
                minZoom={0.35}
                maxZoom={1.6}
                onNodeClick={handleTopologyNodeClick}
                onNodeDrag={handleTopologyNodeDrag}
                onNodeDragStop={handleTopologyNodeDragStop}
                onEdgeClick={handleTopologyEdgeClick}
              >
                <Background color="#c9d7de" gap={18} />
              </ReactFlow>
            )}
          </div>
        </section>

        <div className="nodeList" aria-label="按地域分组的节点列表">
          <div className="regionIndex" aria-label="地域快捷导航">
            {nodeRegionGroups.map((group) => (
              <button
                key={group.id}
                type="button"
                className="secondary"
                onClick={() => {
                  document.querySelector(`[data-region-id="${group.id}"]`)?.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                  });
                }}
              >
                <span>{group.region}</span>
                <small>{group.nodes.length}</small>
              </button>
            ))}
          </div>
          {nodeRegionGroups.map((group) => (
            <section key={group.id} className="regionGroup" data-region-id={group.id}>
              <header className="regionHeader">
                <div>
                  <h3>{group.region}</h3>
                  <p className="muted">{group.onlineCount} online / {group.nodes.length} total</p>
                </div>
              </header>
              <div className="regionNodeList">
                {group.nodes.map((node) => {
                  const expanded = node.id === selectedNodeId;
                  const online = isNodeSelectable(node);
                  return (
                    <section key={node.id} data-node-id={node.id} className={expanded ? "nodeCard expanded" : "nodeCard"}>
                      <div className="nodeBar">
                        <button
                          className="nodeHeader"
                          disabled={!online}
                          onClick={() => {
                            setSelectedNodeId(expanded ? null : node.id);
                            setSelectedConfigId(null);
                            setPlan(null);
                            setImportCandidatesExpanded(false);
                          }}
                        >
                          <span>
                            <strong>{node.name}</strong>
                            <small>{nodeEndpointOptions(node).join(", ") || node.hostname || "未配置入口地址"}</small>
                          </span>
                          <span className={online ? "statusBadge online" : "statusBadge"}>{node.status}</span>
                        </button>
                        <button
                          className="iconButton nodeEditButton"
                          title="编辑节点"
                          onClick={() => setEditingNodeId(node.id)}
                        >
                          <Pencil size={16} />
                        </button>
                      </div>

                      {expanded && (
                        <div className="nodeDetails">
                          {!selectedNodeOnline && <div className="empty">Agent 已离线，当前节点暂不能修改或部署。</div>}
                          <section className="connectionActions" aria-label="创建连接">
                            <div>
                              <h3>创建连接</h3>
                              <p className="muted">手动连接用于接入非受管节点；受管连接会自动生成密钥、部署并启动双方接口。</p>
                            </div>
                            <div className="actionRow">
                              <button
                                type="button"
                                disabled={!selectedNodeOnline}
                                onClick={() => setCreateDialog("external")}
                              >
                                <Plus size={16} /> 手动创建连接
                              </button>
                              <button
                                type="button"
                                disabled={!selectedNodeOnline || nodes.filter((item) => item.id !== node.id && isNodeSelectable(item)).length === 0}
                                onClick={() => openManagedCreateDialog()}
                              >
                                <GitBranch size={16} /> 创建受管连接
                              </button>
                            </div>
                          </section>

                          {selectedNodeSupportsWgQuickImport ? (
                            <div className="sectionActions">
                              <button
                                className="secondary"
                                disabled={!selectedNodeOnline || actionPending(nodeActionKey(selectedNodeId, "import-scan"))}
                                onClick={() => void runAction(requestImportScan, nodeActionKey(selectedNodeId, "import-scan"))}
                              >
                                <Upload size={16} /> {actionPending(nodeActionKey(selectedNodeId, "import-scan")) ? "扫描中" : "扫描现有 wg-quick"}
                              </button>
                            </div>
                          ) : (
                            <div className="empty">{importScanUnavailableMessage(selectedNode, selectedNodeOnline)}</div>
                          )}

                          {selectedNodeSupportsWgQuickImport && importCandidates.length > 0 && (
                            <div className="candidateList">
                              <button
                                type="button"
                                className="candidateToggle"
                                onClick={() => setImportCandidatesExpanded((value) => !value)}
                              >
                                <span>
                                  {importCandidatesExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                  <strong>扫描到的 wg-quick 配置</strong>
                                </span>
                                <small>{importCandidates.length} 个</small>
                              </button>
                              {importCandidatesExpanded && importCandidates.map((candidate) => (
                                <div key={candidate.id} className="candidate">
                                  <div>
                                    <strong>{candidate.interface_name}</strong>
                                    <span>{candidate.path}</span>
                                    {candidate.warnings.length > 0 && <small>{candidate.warnings.join("; ")}</small>}
                                  </div>
                                  <button
                                    disabled={candidate.imported || !selectedNodeOnline || actionPending(candidateActionKey(candidate.id))}
                                    onClick={() => void runAction(() => importCandidate(candidate.id), candidateActionKey(candidate.id))}
                                  >
                                    {candidate.imported ? "已导入" : actionPending(candidateActionKey(candidate.id)) ? "导入中" : "导入"}
                                  </button>
                                </div>
                              ))}
                            </div>
                          )}

                          <div className="configList">
                            {configs.length === 0 ? (
                              <div className="empty">该节点还没有 WireGuard 配置。</div>
                            ) : (
                              configs.map((item) => (
                                <button
                                  key={item.id}
                                  data-config-id={item.id}
                                  className="configRow"
                                  onClick={() => {
                                    setSelectedConfigId(item.id);
                                    setPlan(null);
                                  }}
                                >
                                  <span>
                                    <strong>{item.name}</strong>
                                    <small>{item.source}{item.managed ? " / managed" : " / unmanaged"}</small>
                                  </span>
                                  <span className="configRowMetrics">
                                    <span className={`statusBadge ${item.runtime_status === "running" ? "online" : ""}`}>
                                      {statusLabel(item.runtime_status)}
                                    </span>
                                    <MonitorSummaryButton
                                      summary={item.monitor_summary}
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        setMonitorDialogConfigId(item.id);
                                        setMonitorWindow("1h");
                                      }}
                                    />
                                  </span>
                                </button>
                              ))
                            )}
                          </div>
                        </div>
                      )}
                    </section>
                  );
                })}
              </div>
            </section>
          ))}
        </div>
      </section>

      {selectedConfig && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel" role="dialog" aria-modal="true" aria-labelledby="peer-modal-title">
            <header className="modalHeader">
              <div>
                <h2 id="peer-modal-title">Peer 配置</h2>
                <p className="muted">{selectedNode.name} / {selectedConfig.name} / {statusLabel(selectedConfig.runtime_status)}</p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  setSelectedConfigId(null);
                  setPlan(null);
                }}
              >
                <X size={18} />
              </button>
            </header>

            {!selectedNodeOnline && <div className="empty">Agent 已离线，提交时后端会拒绝部署相关操作。</div>}

            {selectedConfigIsUnmanagedImport ? (
              <section className="modalSection">
                <h3>导入观察记录</h3>
                <div className="empty">该配置来自节点现有 wg-quick 文件，尚未归属 Link42 管理。接管或导入为受管连接前，系统不会修改、启停或删除节点上的原始配置文件。</div>
              </section>
            ) : selectedConfigIsManagedLink && managedLink ? (
              <section className="modalSection">
                <h3>受管连接</h3>
                <form
                  key={`managed-edit-${selectedConfig.id}-${managedLink.peer_interface.id}`}
                  onSubmit={(event) => void runAction(() => saveManagedLink(event), configActionKey(selectedConfig.id, "save-managed-link"))}
                  className="gridForm describedForm"
                >
                  <FormSection title="接口与隧道地址" hint="这里决定双方 WireGuard 接口本身的名称、Address 和可选监听端口。">
                    <Field label="本端接口名称" hint={`当前节点：${selectedNode.name}`}>
                      <input name="local_interface_name" defaultValue={managedLink.local_interface.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端接口名称" hint={`对端节点：${selectedManagedLinkPeerNode?.name || managedLink.peer_interface.node_id}`}>
                      <input name="peer_interface_name" defaultValue={managedLink.peer_interface.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端隧道地址" hint="本端 WireGuard Address；支持多个 CIDR，用逗号分隔。">
                      <input name="local_tunnel_ips" defaultValue={managedLink.local_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端隧道地址" hint="对端 WireGuard Address；支持多个 CIDR，用逗号分隔。">
                      <input name="peer_tunnel_ips" defaultValue={managedLink.peer_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端监听端口" hint="可选；留空表示本端 WireGuard 不写 ListenPort。udp2raw server 在本端时必须填写。">
                      <input name="local_listen_port" defaultValue={managedLink.local_interface.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端监听端口" hint="可选；留空表示对端 WireGuard 不写 ListenPort。udp2raw server 在对端时必须填写。">
                      <input name="peer_listen_port" defaultValue={managedLink.peer_interface.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="直连入口与路由" hint="直连和 mimic 使用这里的真实 Endpoint；只有 udp2raw 会把 Endpoint 接管到本地 client。">
                    <Field label="本端入口地址" hint="对端连接本节点时使用。">
                      <EndpointSelect
                        key={`edit-local-endpoint-${editLocalEndpointDefault}`}
                        name="local_endpoint_host"
                        defaultValue={editLocalEndpointDefault}
                        placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                        options={editLocalEndpointOptions}
                        disabled={!selectedNodeOnline}
                        locked={udp2rawActive}
                      />
                    </Field>
                    <Field label="本端 Endpoint 端口" hint="对端直连本节点时使用；留空则使用本端 ListenPort。">
                      <input
                        name="local_endpoint_port"
                        defaultValue={managedLink.peer_peer.endpoint_port || managedLink.local_interface.listen_port || ""}
                        inputMode="numeric"
                        disabled={!selectedNodeOnline || udp2rawActive}
                      />
                    </Field>
                    <Field label="对端入口地址" hint="本端连接对端节点时使用。">
                      <EndpointSelect
                        key={`edit-peer-endpoint-${editPeerEndpointDefault}`}
                        name="peer_endpoint_host"
                        defaultValue={editPeerEndpointDefault}
                        placeholder={selectedManagedLinkPeerEndpoints[0] || "203.0.113.20"}
                        options={editPeerEndpointOptions}
                        disabled={!selectedNodeOnline}
                        locked={udp2rawActive}
                      />
                    </Field>
                    <Field label="对端 Endpoint 端口" hint="本端直连对端节点时使用；留空则使用对端 ListenPort。">
                      <input
                        name="peer_endpoint_port"
                        defaultValue={managedLink.local_peer.endpoint_port || managedLink.peer_interface.listen_port || ""}
                        inputMode="numeric"
                        disabled={!selectedNodeOnline || udp2rawActive}
                      />
                    </Field>
                    <Field label="本端 Peer AllowedIPs" hint="写入当前节点 [Peer]；声明经对端到达的地址段。">
                      <input name="local_allowed_ips" defaultValue={managedLink.local_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端 Peer AllowedIPs" hint="写入对端节点 [Peer]；声明经本端到达的地址段。">
                      <input name="peer_allowed_ips" defaultValue={managedLink.peer_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="连接中间层" hint="udp2raw 通过本地代理接管 Endpoint；mimic 在网卡层透明处理真实 Endpoint 流量。">
                    <Field label="中间层类型" hint="mimic 需要双方节点为非 OpenWrt Linux kernel > 6.1 且已安装 mimic。">
                      <select
                        value={middlewareType}
                        disabled={!selectedNodeOnline}
                        onChange={(event) => {
                          const next = event.currentTarget.value as "none" | "udp2raw" | "mimic";
                          setMiddlewareType(next);
                          setUdp2rawEnabled(next === "udp2raw");
                          setMimicEnabled(next === "mimic");
                        }}
                      >
                        <option value="none">不使用中间层</option>
                        <option value="udp2raw">udp2raw</option>
                        <option value="mimic">mimic</option>
                      </select>
                    </Field>
                  </FormSection>
                  {middlewareType === "udp2raw" && (
                    <Udp2RawFields
                      enabled={udp2rawEnabled}
                      serverSide={udp2rawServerSide}
                      localListenPort={managedLink.local_interface.listen_port}
                      peerListenPort={managedLink.peer_interface.listen_port}
                      defaults={managedLink.middleware?.type === "udp2raw" ? managedLink.middleware : null}
                      disabled={!selectedNodeOnline}
                      onEnabledChange={setUdp2rawEnabled}
                      onServerSideChange={setUdp2rawServerSide}
                    />
                  )}
                  {middlewareType === "mimic" && (
                    <MimicFields
                      enabled={mimicEnabled}
                      defaults={managedLink.middleware?.type === "mimic" ? managedLink.middleware : null}
                      localNode={selectedNode}
                      peerNode={selectedManagedLinkPeerNode}
                      disabled={!selectedNodeOnline}
                      onEnabledChange={setMimicEnabled}
                    />
                  )}
                  <FormSection title="链路参数" hint="Table=off 是 DN42 常用默认值；PersistentKeepalive 会写入双方 Peer。">
                    <Field label="MTU" hint={udp2rawActive ? "启用 udp2raw 时建议降低 MTU；可手动修改。" : mimicActive ? "启用 mimic 时建议将 IPv6 WireGuard MTU 降到 1408，可手动修改。" : "双方链路 MTU，默认 1420。"}>
                      <input name="mtu" defaultValue={managedLink.local_interface.mtu || managedLink.peer_interface.mtu || 1420} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                      <RouteModeSelect defaultValue={managedLink.local_interface.table_name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="PersistentKeepalive" hint="可选；NAT 场景常用 25。">
                      <input name="persistent_keepalive" placeholder="25" defaultValue={managedLink.local_peer.persistent_keepalive || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="高级配置" hint="这些内容会原样追加到对应的 [Interface] 或 [Peer] 区块，请只填写 WireGuard 支持的配置行。">
                    <Field label="本端 Interface 高级配置" hint="写入当前节点 [Interface] 后，例如 PostUp。不同节点可不同。" wide>
                      <textarea name="local_interface_custom_config" defaultValue={managedLink.local_interface.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端 Peer 高级配置" hint="写入当前节点 [Peer] 后。" wide>
                      <textarea name="local_peer_custom_config" defaultValue={managedLink.local_peer.peer_custom_config || ""} placeholder="AllowedIPs 之外的自定义 Peer 行" disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端 Interface 高级配置" hint="写入对端节点 [Interface] 后，例如不同的 PostUp。" wide>
                      <textarea name="peer_interface_custom_config" defaultValue={managedLink.peer_interface.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端 Peer 高级配置" hint="写入对端节点 [Peer] 后。" wide>
                      <textarea name="peer_peer_custom_config" defaultValue={managedLink.peer_peer.peer_custom_config || ""} placeholder="AllowedIPs 之外的自定义 Peer 行" disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-managed-link"))}>
                    <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-managed-link")) ? "下发中" : "保存并下发双方配置"}
                  </button>
                </form>
              </section>
            ) : (
              <>
                <section className="modalSection">
                  <h3>WireGuard 配置</h3>
                  <form
                    key={`edit-${selectedConfig.id}`}
                    onSubmit={(event) => void runAction(() => saveConfig(event, "update"), configActionKey(selectedConfig.id, "save-config"))}
                    className="gridForm describedForm"
                  >
                    <Field label="接口名称" hint="节点上的 wg-quick 接口名，例如 wg0。">
                      <input name="name" placeholder="wg0" defaultValue={selectedConfig.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端隧道地址" hint="CIDR 格式，多个地址用逗号分隔。">
                      <input name="tunnel_ips" placeholder="10.42.0.1/24" defaultValue={selectedConfig.tunnel_ips.join(", ")} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="监听端口" hint="UDP 端口，留空表示不写 ListenPort。">
                      <input name="listen_port" placeholder="51820" defaultValue={selectedConfig.listen_port || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="MTU" hint="链路 MTU，默认 1420。">
                      <input name="mtu" placeholder="1420" defaultValue={selectedConfig.mtu || 1420} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                      <RouteModeSelect defaultValue={selectedConfig.table_name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端公钥" hint="44 位 base64；受管连接会自动生成。">
                      <input name="public_key" placeholder="base64 public key" defaultValue={selectedConfig.public_key || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端私钥" hint="可信面板会明文保存并渲染到配置文件。" wide>
                      <textarea name="private_key" placeholder="base64 private key" defaultValue={selectedConfig.private_key_value || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="Interface 高级配置" hint="逐行写入 [Interface] 后，例如 PostUp/PostDown。不会做语义校验。" wide>
                      <textarea name="interface_custom_config" placeholder="PostUp = ..." defaultValue={selectedConfig.interface_custom_config || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-config"))}>
                      <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-config")) ? "保存中" : "保存配置修改"}
                    </button>
                  </form>
                </section>

                <section className="modalSection">
                  <h3>唯一对端</h3>
                  <form
                    key={`${selectedConfigId || "none"}-${peer?.id || "new"}`}
                    onSubmit={(event) => void runAction(() => savePeer(event), configActionKey(selectedConfig.id, "save-peer"))}
                    className="gridForm describedForm"
                  >
                    <Field label="对端名称" hint="可选，仅用于界面识别。">
                      <input name="name" placeholder="remote-site" defaultValue={peer?.name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端公钥" hint="必填，44 位 base64。">
                      <input name="public_key" placeholder="base64 public key" defaultValue={peer?.public_key || ""} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="预共享密钥" hint="可选，填写后会渲染 PresharedKey。">
                      <input name="preshared_key" placeholder="base64 preshared key" defaultValue={peer?.preshared_key_value || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="AllowedIPs" hint="CIDR 格式，多个值用逗号分隔。">
                      <input name="allowed_ips" placeholder="10.42.0.2/32" defaultValue={peer?.allowed_ips.join(", ") || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="Endpoint Host" hint="对端公网 IP、内网 IP 或域名；可留空。">
                      <input name="endpoint_host" placeholder="203.0.113.20" defaultValue={peer?.endpoint_host || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="Endpoint Port" hint="对端 UDP 端口；Host 留空时通常也留空。">
                      <input name="endpoint_port" placeholder="51820" defaultValue={peer?.endpoint_port || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="PersistentKeepalive" hint="常用 25；留空表示不写。">
                      <input name="persistent_keepalive" placeholder="25" defaultValue={peer?.persistent_keepalive || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="Peer 高级配置" hint="逐行写入 [Peer] 后，例如自定义标记行。不会做语义校验。" wide>
                      <textarea name="peer_custom_config" placeholder="自定义 Peer 行" defaultValue={peer?.peer_custom_config || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-peer"))}>
                      <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-peer")) ? "保存中" : "保存唯一对端"}
                    </button>
                  </form>
                  <div className="peerList">
                    {peer ? (
                      <div className="peer">
                        <strong>{peer.name || peer.public_key.slice(0, 12)}</strong>
                        <span>{peer.allowed_ips.join(", ") || "无 AllowedIPs"}</span>
                      </div>
                    ) : (
                      <div className="empty">尚未设置对端。每个 WireGuard 配置需要且只能有一个对端。</div>
                    )}
                  </div>
                </section>
              </>
            )}

            <section className="modalSection">
              <h3>部署与连接</h3>
              {!selectedConfigIsManagedLink && (
                <>
                  {selectedConfigIsUnmanagedImport && (
                    <>
                  <button className="secondary" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfigId, "take-over"))} onClick={() => void runAction(takeOverConfig, configActionKey(selectedConfigId, "take-over"))}>
                    <Upload size={16} /> {actionPending(configActionKey(selectedConfigId, "take-over")) ? "接管中" : "接管导入配置"}
                      </button>
                      <button
                        className="secondary"
                        disabled={!selectedNodeOnline}
                        onClick={() => {
                          setSelectedConfigId(null);
                          setPlan(null);
                          openManagedCreateDialog({ replaceLocalConfigId: selectedConfig.id });
                        }}
                      >
                        <GitBranch size={16} /> 导入为受管连接
                      </button>
                    </>
                  )}
                  {!selectedConfigIsUnmanagedImport && (
                    <button disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfigId, "create-plan"))} onClick={() => void runAction(createApplyPlan, configActionKey(selectedConfigId, "create-plan"))}>
                      <GitBranch size={16} /> {actionPending(configActionKey(selectedConfigId, "create-plan")) ? "生成中" : "生成部署计划"}
                    </button>
                  )}
                </>
              )}
              {selectedConfigIsManagedLink && (
                <div className="empty">受管连接由系统直接管理，保存修改会立即下发双方配置，不需要生成部署计划。</div>
              )}
              <div className="actionRow">
                {!selectedConfigIsManagedLink && !selectedConfigIsUnmanagedImport && (
                  <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || actionPending(configActionKey(selectedConfigId, "refresh-deployed"))} onClick={() => void runAction(refreshDeployedConfig, configActionKey(selectedConfigId, "refresh-deployed"))}>
                    <RefreshCw size={16} /> {actionPending(configActionKey(selectedConfigId, "refresh-deployed")) ? "同步中" : "同步节点配置"}
                  </button>
                )}
                {!selectedConfigIsUnmanagedImport && (
                  <>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigRunning || actionPending(configActionKey(selectedConfigId, "start"))} onClick={() => void runAction(startSelectedConfig, configActionKey(selectedConfigId, "start"))}>
                      {actionPending(configActionKey(selectedConfigId, "start")) || selectedConfig.runtime_status === "starting" ? "启动中" : selectedConfigIsManagedLink ? "启动双方连接" : "启动连接"}
                    </button>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigStopped || actionPending(configActionKey(selectedConfigId, "stop"))} onClick={() => void runAction(stopSelectedConfig, configActionKey(selectedConfigId, "stop"))}>
                      {actionPending(configActionKey(selectedConfigId, "stop")) || selectedConfig.runtime_status === "stopping" ? "断开中" : selectedConfigIsManagedLink ? "断开双方连接" : "断开连接"}
                    </button>
                  </>
                )}
                <button className="danger" disabled={selectedConfigIsUnmanagedImport ? selectedConfigAnyTaskPending : (!selectedNodeOnline || isConfigBusy || !isConfigStopped || selectedConfigAnyTaskPending)} onClick={() => void runAction(openDeleteDialog)}>
                  {selectedConfigIsManagedLink ? "删除双方配置" : selectedConfigIsUnmanagedImport ? "删除观察记录" : "删除配置"}
                </button>
              </div>
              {!selectedConfigIsManagedLink && plan && (
                <div className="plan">
                  <h3>{plan.title}</h3>
                  <p>{plan.summary}</p>
                  <p className="muted">计划状态：{plan.status}{plan.task_status ? ` / 任务：${plan.task_status}` : ""}</p>
                  <pre>{plan.diff || "此计划没有配置 diff。"}</pre>
                  {plan.task_result && <pre>{JSON.stringify(plan.task_result, null, 2)}</pre>}
                  <button disabled={!selectedNodeOnline || plan.status !== "draft" || !hasDeployDiff || actionPending(configActionKey(selectedConfigId, "confirm-plan"))} onClick={() => void runAction(confirmPlan, configActionKey(selectedConfigId, "confirm-plan"))}>
                    <Check size={16} /> {actionPending(configActionKey(selectedConfigId, "confirm-plan")) ? "执行中" : "确认执行"}
                  </button>
                </div>
              )}
            </section>
          </section>
        </div>
      )}

      {monitorDialogConfig && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel monitorModal" role="dialog" aria-modal="true" aria-labelledby="monitor-title">
            <header className="modalHeader">
              <div>
                <h2 id="monitor-title"><LineChartIcon size={18} /> 链路延迟统计</h2>
                <p className="muted">{selectedNode?.name || "节点"} / {monitorDialogConfig.name}</p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  setMonitorDialogConfigId(null);
                  setMonitorDetail(null);
                }}
              >
                <X size={18} />
              </button>
            </header>
            <form
              key={`monitor-${monitorDialogConfig.id}-${monitorDetail?.monitor.id || "new"}`}
              className="gridForm describedForm"
              onSubmit={(event) => void runAction(() => saveLinkMonitor(event), monitorActionKey(monitorDialogConfig.id, "save"))}
            >
              <Field label="目标 IP" hint="从当前节点 Agent 发起 ping；建议填写对端隧道 IP，第一版只支持 IP。">
                <input
                  name="target_host"
                  placeholder="10.42.0.2"
                  defaultValue={monitorDetail?.monitor.target_host || suggestedMonitorTarget(monitorDialogConfig, peer)}
                  required
                />
              </Field>
              <Field label="刷新频率" hint="1-300 秒，默认 10 秒。">
                <input name="interval_seconds" inputMode="numeric" defaultValue={monitorDetail?.monitor.interval_seconds || 10} required />
              </Field>
              <Field label="保留时间" hint="历史样本保留天数，例如 1、7、30。">
                <select name="retention_days" defaultValue={monitorDetail?.monitor.retention_days || 7}>
                  <option value="1">1 天</option>
                  <option value="7">7 天</option>
                  <option value="30">30 天</option>
                  <option value="90">90 天</option>
                </select>
              </Field>
              <label className="checkField">
                <input name="enabled" type="checkbox" defaultChecked={monitorDetail?.monitor.enabled ?? true} />
                <span>启用监测</span>
              </label>
              <div className="actionRow wideField">
                <button type="submit" disabled={actionPending(monitorActionKey(monitorDialogConfig.id, "save"))}>
                  <Check size={16} /> {actionPending(monitorActionKey(monitorDialogConfig.id, "save")) ? "保存中" : "保存监测"}
                </button>
                {monitorDetail && (
                  <button
                    type="button"
                    className="danger"
                    disabled={actionPending(monitorActionKey(monitorDialogConfig.id, "delete"))}
                    onClick={() => void runAction(deleteLinkMonitor, monitorActionKey(monitorDialogConfig.id, "delete"))}
                  >
                    {actionPending(monitorActionKey(monitorDialogConfig.id, "delete")) ? "删除中" : "删除监测"}
                  </button>
                )}
              </div>
            </form>

            <div className="monitorToolbar">
              {["1h", "6h", "1d", "7d", "30d"].map((item) => (
                <button
                  key={item}
                  type="button"
                  className={monitorWindow === item ? "" : "secondary"}
                  onClick={() => setMonitorWindow(item)}
                >
                  {item}
                </button>
              ))}
            </div>

            {monitorDetail?.summary ? (
              <>
                <div className="monitorStats">
                  <span><strong>{formatLatency(monitorDetail.summary.last_latency_ms)}</strong><small>当前延迟</small></span>
                  <span><strong>{formatLatency(monitorDetail.summary.avg_latency_ms)}</strong><small>平均延迟</small></span>
                  <span><strong>{formatLatency(monitorDetail.summary.jitter_ms)}</strong><small>抖动</small></span>
                  <span><strong>{formatLoss(monitorDetail.summary.packet_loss)}</strong><small>丢包率</small></span>
                  <span><strong>{monitorDetail.summary.stability_score}</strong><small>稳定度</small></span>
                </div>
                <div className="monitorChart">
                  <ResponsiveContainer width="100%" height={280}>
                    <LineChart
                      data={monitorDetail.samples.map((sample) => ({
                        time: new Date(sample.checked_at).toLocaleString(),
                        latency: sample.success ? sample.latency_ms : null,
                        status: sample.success ? "ok" : sample.error || "loss",
                      }))}
                      margin={{ top: 10, right: 18, bottom: 4, left: 0 }}
                    >
                      <CartesianGrid stroke="#dce4e8" strokeDasharray="3 3" />
                      <XAxis dataKey="time" tick={{ fontSize: 11 }} minTickGap={42} />
                      <YAxis tick={{ fontSize: 11 }} unit="ms" />
                      <Tooltip />
                      <Line type="monotone" dataKey="latency" name="延迟" stroke="#216f86" strokeWidth={2} dot={false} connectNulls={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </>
            ) : (
              <div className="empty">尚无监测数据。保存监测后，Agent 会按刷新频率上报延迟样本。</div>
            )}
          </section>
        </div>
      )}

      {deleteDialogOpen && selectedConfig && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="delete-config-title">
            <header className="modalHeader">
              <div>
                <h2 id="delete-config-title">删除配置</h2>
                <p className="muted">{selectedNode?.name || "节点"} / {selectedConfig.name}</p>
              </div>
              <button className="iconButton" onClick={() => setDeleteDialogOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <div className="stack">
              <div className="empty">
                {selectedConfigIsManagedLink
                  ? "将从 Link42 中删除这条受管连接的双方记录。默认保留节点上的 WireGuard 配置和服务，之后仍可通过导入重新发现。"
                  : selectedConfigIsUnmanagedImport
                    ? "将只删除这条导入观察记录，不会修改节点上的原始配置文件或服务。"
                    : "将从 Link42 中删除这条 WireGuard 记录。默认保留节点上的配置文件和服务，之后仍可通过导入重新发现。"}
              </div>
              {!selectedConfigIsUnmanagedImport && (
                <label className="checkField dangerCheck">
                  <input
                    type="checkbox"
                    checked={deleteNodeConfig}
                    onChange={(event) => setDeleteNodeConfig(event.currentTarget.checked)}
                  />
                  <span>同时删除节点上的 WireGuard 配置文件和服务</span>
                </label>
              )}
              <div className="actionRow">
                <button className="secondary" onClick={() => setDeleteDialogOpen(false)}>取消</button>
                <button
                  className="danger"
                  disabled={actionPending(configActionKey(selectedConfig.id, "delete"))}
                  onClick={() => void runAction(deleteSelectedConfig, configActionKey(selectedConfig.id, "delete"))}
                >
                  {actionPending(configActionKey(selectedConfig.id, "delete"))
                    ? "删除中"
                    : deleteNodeConfig ? "删除记录并清理节点" : "仅删除 Link42 记录"}
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
