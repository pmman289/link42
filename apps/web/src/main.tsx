import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, ChevronDown, ChevronRight, GitBranch, LogOut, Pencil, Plus, RefreshCw, Server, Settings, Upload, X } from "lucide-react";
import CreatableSelect from "react-select/creatable";
import type { SingleValue, StylesConfig } from "react-select";
import "./styles.css";

type NodeItem = {
  id: number;
  name: string;
  hostname: string | null;
  management_ip: string | null;
  public_ip: string | null;
  endpoint_ips: string[];
  agent_token_value: string | null;
  agent_version: string | null;
  agent_protocol_version: number | null;
  agent_capabilities: string[];
  agent_platform: Record<string, unknown>;
  agent_update_status: string | null;
  agent_last_error: string | null;
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
  warnings: string[];
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
  middleware: Udp2RawMiddleware | null;
};

type Udp2RawMiddleware = {
  type: "udp2raw";
  enabled: boolean;
  server_side: "local" | "peer";
  server_listen_host: string;
  server_connect_host: string | null;
  server_listen_port: number;
  client_listen_host: string;
  client_listen_port: number;
  raw_mode: string;
  cipher_mode: string;
  password: string;
  auto_rule: boolean;
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
};

type Toast = {
  id: number;
  type: "success" | "error" | "info";
  text: string;
};

// API 基础路径；同端口托管时使用当前 origin，Vite 预览时推断 FastAPI 的 8000 端口。
const INFERRED_API_BASE =
  window.location.port === "5173"
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : window.location.origin;
const API_BASE =
  import.meta.env.VITE_LINK42_API_BASE ||
  INFERRED_API_BASE;

// 默认主控地址；节点 Agent 从本机访问时通常使用 127.0.0.1。
const DEFAULT_CONTROLLER_URL =
  import.meta.env.VITE_LINK42_CONTROLLER_URL || API_BASE;
const AUTH_TOKEN_KEY = "link42.authToken";
const AUTH_EXPIRED_EVENT = "link42:auth-expired";

function splitList(value: string): string[] {
  // 将输入框中的逗号分隔内容转换成 API 需要的数组。
  return value
    .split(",")
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
    ...(importedHost ? [{ value: importedHost, label: "原始 Endpoint", source: "imported" as const }] : []),
    ...(currentHost ? [{ value: currentHost, label: "当前配置", source: "current" as const }] : []),
    ...nodeHosts.map((host) => ({ value: host, label: "节点地址", source: "node" as const })),
  ]);
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
            <small>{option.label}</small>
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

function RouteModeSelect({
  defaultValue = "off",
  disabled,
}: {
  defaultValue?: string | null;
  disabled?: boolean;
}) {
  return (
    <select name="table_name" defaultValue={defaultValue || ""} disabled={disabled}>
      <option value="">自动生成路由（默认）</option>
      <option value="off">不自动生成路由（Table=off）</option>
    </select>
  );
}

function Udp2RawFields({
  enabled,
  serverSide,
  defaults,
  disabled,
  onEnabledChange,
  onServerSideChange,
}: {
  enabled: boolean;
  serverSide: "local" | "peer";
  defaults?: Partial<Udp2RawMiddleware> | null;
  disabled?: boolean;
  onEnabledChange: (value: boolean) => void;
  onServerSideChange: (value: "local" | "peer") => void;
}) {
  return (
    <>
      <label className="checkField wideField">
        <input
          name="udp2raw_enabled"
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={(event) => onEnabledChange(event.currentTarget.checked)}
        />
        <span>启用 udp2raw 连接中间层</span>
      </label>
      {enabled && (
        <>
          <Field label="udp2raw server 所在节点" hint="server 接收 raw TCP/faketcp/icmp，再转回本机 WireGuard UDP。">
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
          <Field label="server 监听 IP" hint="udp2raw -l 使用的本机 IP；必须是 IP，不能填域名。">
            <input name="udp2raw_server_listen_host" defaultValue={defaults?.server_listen_host || "0.0.0.0"} disabled={disabled} />
          </Field>
          <Field label="server 对外 IP" hint="client 连接 udp2raw server 的 IP；必须是 IP，不能填域名。">
            <input name="udp2raw_server_connect_host" defaultValue={defaults?.server_connect_host || ""} placeholder="203.0.113.20" disabled={disabled} />
          </Field>
          <Field label="server 监听端口" hint="client 要连接的 udp2raw raw 端口。">
            <input name="udp2raw_server_listen_port" defaultValue={defaults?.server_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="client 本地 UDP 监听 IP" hint="WireGuard Endpoint 会指向这个本地 UDP 地址；通常是 127.0.0.1。">
            <input name="udp2raw_client_listen_host" defaultValue={defaults?.client_listen_host || "127.0.0.1"} disabled={disabled} />
          </Field>
          <Field label="client 本地 UDP 监听端口" hint="client 从这里接收 WireGuard UDP 包，再封装发往 server。">
            <input name="udp2raw_client_listen_port" defaultValue={defaults?.client_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="raw mode">
            <select name="udp2raw_raw_mode" defaultValue={defaults?.raw_mode || "faketcp"} disabled={disabled}>
              <option value="faketcp">faketcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </select>
          </Field>
          <Field label="cipher mode">
            <select name="udp2raw_cipher_mode" defaultValue={defaults?.cipher_mode || "xor"} disabled={disabled}>
              <option value="xor">xor</option>
              <option value="aes128cbc">aes128cbc</option>
              <option value="none">none</option>
            </select>
          </Field>
          <Field label="密码" hint="留空由主控自动生成；保存后会复用当前值。">
            <input name="udp2raw_password" defaultValue={defaults?.password || ""} disabled={disabled} />
          </Field>
          <label className="checkField wideField">
            <input name="udp2raw_auto_rule" type="checkbox" defaultChecked={defaults?.auto_rule ?? true} disabled={disabled} />
            <span>允许 udp2raw 自动添加 iptables 规则（-a）</span>
          </label>
          <div className="empty wideField">
            {serverSide === "peer"
              ? "本端 WireGuard Endpoint 由 udp2raw client 接管，指向本端 127.0.0.1；对端 udp2raw server 转发到对端 WireGuard ListenPort。"
              : "对端 WireGuard Endpoint 由 udp2raw client 接管，指向对端 127.0.0.1；本端 udp2raw server 转发到本端 WireGuard ListenPort。"}
          </div>
        </>
      )}
    </>
  );
}

function readUdp2RawForm(form: FormData): Record<string, unknown> | null {
  const enabled = form.get("udp2raw_enabled") === "on";
  if (!enabled) return null;
  return {
    enabled: true,
    server_side: String(form.get("udp2raw_server_side") || "peer"),
    server_listen_host: String(form.get("udp2raw_server_listen_host") || "0.0.0.0").trim(),
    server_connect_host: String(form.get("udp2raw_server_connect_host") || "").trim() || null,
    server_listen_port: optionalInt(form.get("udp2raw_server_listen_port")),
    client_listen_host: String(form.get("udp2raw_client_listen_host") || "127.0.0.1").trim(),
    client_listen_port: optionalInt(form.get("udp2raw_client_listen_port")),
    raw_mode: String(form.get("udp2raw_raw_mode") || "faketcp"),
    cipher_mode: String(form.get("udp2raw_cipher_mode") || "xor"),
    password: String(form.get("udp2raw_password") || "").trim() || null,
    auto_rule: form.get("udp2raw_auto_rule") === "on",
  };
}

function validateUdp2RawForm(udp2raw: Record<string, unknown> | null, localListenPort: number | null, peerListenPort: number | null) {
  if (!udp2raw) return;
  const serverSide = String(udp2raw.server_side);
  const serverListenHost = String(udp2raw.server_listen_host || "");
  const serverConnectHost = String(udp2raw.server_connect_host || "");
  const clientListenHost = String(udp2raw.client_listen_host || "");
  if (!isValidPort(Number(udp2raw.server_listen_port) || null) || !isValidPort(Number(udp2raw.client_listen_port) || null)) {
    throw new Error("udp2raw server 端口和 client 本地 UDP 监听端口必须填写 1-65535 之间的整数");
  }
  if (!isProbablyIpAddress(serverListenHost) || !isProbablyIpAddress(clientListenHost)) {
    throw new Error("udp2raw 监听地址必须填写 IP，不能填写域名");
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
  const [controllerUrl, setControllerUrl] = useState(DEFAULT_CONTROLLER_URL);
  const [settingsUsername, setSettingsUsername] = useState("pmman");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [nodes, setNodes] = useState<NodeItem[]>([]);
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
  const [udp2rawEnabled, setUdp2rawEnabled] = useState(false);
  const [udp2rawServerSide, setUdp2rawServerSide] = useState<"local" | "peer">("peer");
  const [peerNodeConfigs, setPeerNodeConfigs] = useState<ConfigItem[]>([]);
  const [importCandidatesExpanded, setImportCandidatesExpanded] = useState(false);
  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) || null,
    [nodes, selectedNodeId],
  );
  const selectedConfig = useMemo(
    () => configs.find((item) => item.id === selectedConfigId) || null,
    [configs, selectedConfigId],
  );
  const selectedNodeOnline = selectedNode ? isNodeSelectable(selectedNode) : false;
  const editingNode = useMemo(
    () => nodes.find((node) => node.id === editingNodeId) || null,
    [nodes, editingNodeId],
  );
  const isConfigRunning = selectedConfig?.runtime_status === "running";
  const isConfigStopped = !selectedConfig || ["stopped", "unknown"].includes(selectedConfig.runtime_status);
  const isConfigBusy = selectedConfig ? ["starting", "stopping"].includes(selectedConfig.runtime_status) : false;
  const selectedConfigIsManagedLink = selectedConfig?.source === "managed-node";
  const selectedConfigIsUnmanagedImport = selectedConfig?.source === "imported" && !selectedConfig.managed;
  const hasDeployDiff = Boolean(plan?.diff.trim());
  const selectedPeerNodeOptions = selectedNode
    ? nodes.filter((item) => item.id !== selectedNode.id && isNodeSelectable(item))
    : [];
  const selectedManagedPeerNode = selectedPeerNodeOptions.find((item) => item.id === managedPeerNodeId) || null;
  const selectedLocalEndpoints = selectedNode ? nodeEndpointOptions(selectedNode) : [];
  const selectedPeerEndpoints = selectedManagedPeerNode ? nodeEndpointOptions(selectedManagedPeerNode) : [];
  const selectedManagedLinkPeerNode = managedLink
    ? nodes.find((node) => node.id === managedLink.peer_interface.node_id) || null
    : null;
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
    managedLink?.peer_peer.endpoint_host,
  );
  const editPeerEndpointOptions = endpointOptionsFrom(
    null,
    selectedManagedLinkPeerEndpoints,
    managedLink?.local_peer.endpoint_host,
  );

  function notify(type: Toast["type"], text: string) {
    // 右上角 toast 避免把所有消息堆在主页主流程里。
    const id = Date.now() + Math.random();
    setToasts((items) => [...items, { id, type, text }]);
    window.setTimeout(() => {
      setToasts((items) => items.filter((item) => item.id !== id));
    }, type === "error" ? 6000 : 3800);
  }

  function clearAuthenticatedState() {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    setAuthToken("");
    setCurrentUser(null);
    setNodes([]);
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
    setUdp2rawEnabled(false);
    setUdp2rawServerSide("peer");
    setPeerNodeConfigs([]);
    setSettingsOpen(false);
  }

  async function runAction(action: () => Promise<void>) {
    // 所有用户操作都通过这里展示 API 错误，避免点击后页面无反馈。
    try {
      await action();
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("401:")) {
        clearAuthenticatedState();
        return;
      }
      notify("error", error instanceof Error ? error.message : String(error));
    }
  }

  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const result = await api<LoginResult>("/api/auth/login", {
      method: "POST",
      skipAuth: true,
      body: JSON.stringify({
        username: form.get("username"),
        password: form.get("password"),
      }),
    });
    window.localStorage.setItem(AUTH_TOKEN_KEY, result.token);
    setAuthToken(result.token);
    setCurrentUser(result.username);
    await refreshSettings();
    await refreshNodes();
  }

  async function logout() {
    await api<{ status: string }>("/api/auth/logout", { method: "POST" });
    clearAuthenticatedState();
  }

  async function refreshSettings() {
    const data = await api<ControllerSettings>("/api/settings");
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
  }

  async function saveSettings(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const newPassword = String(form.get("new_password") || "");
    const data = await api<ControllerSettings>("/api/settings", {
      method: "PATCH",
      body: JSON.stringify({
        controller_url: String(form.get("controller_url") || "").trim(),
        username: String(form.get("username") || "").trim(),
        new_password: newPassword || null,
      }),
    });
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
    setSettingsOpen(false);
    if (newPassword) {
      clearAuthenticatedState();
      notify("success", "账号已更新，请使用新凭据重新登录。");
      return;
    }
    setCurrentUser(data.username || currentUser);
    notify("success", "设置已保存。");
  }

  async function refreshNodes() {
    // 刷新节点列表；节点必须由用户主动点选，离线节点不能进入下级菜单。
    const data = await api<NodeItem[]>("/api/nodes");
    setNodes(data);
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
        setAuthChecked(true);
        return;
      }
      try {
        const me = await api<{ authenticated: boolean; username: string | null }>("/api/auth/me");
        setCurrentUser(me.username);
        await refreshSettings();
        await refreshNodes();
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
      refreshNodes().catch((error) => {
        if (!(error instanceof Error && error.message.startsWith("401:"))) {
          notify("error", error instanceof Error ? error.message : String(error));
        }
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [selectedNodeId, authToken]);

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
      setSelectedConfigId(null);
      setPlan(null);
      setManagedPeerNodeId(null);
      refreshConfigs(selectedNodeId, null).catch((error) => notify("error", error.message));
      refreshImportCandidates(selectedNodeId).catch((error) => notify("error", error.message));
    } else {
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
    setUdp2rawEnabled(Boolean(managedLink.middleware.enabled));
    setUdp2rawServerSide(managedLink.middleware.server_side || "peer");
  }, [managedLink?.middleware]);

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
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
        endpoint_ips: endpointIps,
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
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
      }),
    });
    setNodes((items) => items.map((item) => item.id === updated.id ? updated : item));
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
    const command = buildAgentCommand(editingNode);
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
    const result = await api<TaskRequestResult>(`/api/nodes/${editingNode.id}/agent/upgrade`, {
      method: "POST",
      body: JSON.stringify({ target_version: agentUpgradePlan.target_version, force: false }),
    });
    notify("success", result.message);
    await refreshNodes();
    await refreshAgentUpgradePlan(editingNode.id);
    if (result.task_id) {
      void pollAgentUpgradeTask(result.task_id, editingNode.id);
    }
  }

  async function pollAgentUpgradeTask(taskId: number, nodeId: number) {
    try {
      for (let attempt = 0; attempt < 45; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
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
    } catch (error) {
      notify("error", error instanceof Error ? error.message : String(error));
    }
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
    const localListenPort = optionalInt(form.get("local_listen_port"));
    const peerListenPort = optionalInt(form.get("peer_listen_port"));
    const mtu = optionalInt(form.get("mtu")) ?? 1420;
    const udp2raw = readUdp2RawForm(form);
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
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!localEndpointHost || !peerEndpointHost) {
      throw new Error("请填写双方用于互联的入口地址");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
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
          peer_endpoint_host: peerEndpointHost,
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
    setUdp2rawEnabled(false);
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
    const keepalive = Number(form.get("persistent_keepalive")) || null;
    const mtu = optionalInt(form.get("mtu")) ?? 1420;
    const udp2raw = readUdp2RawForm(form);
    if (!isValidCidrs(localTunnelIps) || !isValidCidrs(peerTunnelIps)) {
      throw new Error("双方 IP 必须使用 CIDR 格式，例如 10.42.0.1/32, fd42::1/64");
    }
    if (!isValidCidrs(localAllowedIps) || !isValidCidrs(peerAllowedIps)) {
      throw new Error("AllowedIPs 必须使用 CIDR 格式，例如 10.42.0.2/32 或 192.168.10.0/24");
    }
    if (!isValidPort(localListenPort) || !isValidPort(peerListenPort)) {
      throw new Error("双方监听端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535)) {
      throw new Error("PersistentKeepalive 必须是 0-65535 之间的整数");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
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
        peer_endpoint_host: String(form.get("peer_endpoint_host") || "").trim(),
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

  async function deleteSelectedConfig() {
    // 删除配置前做前端确认；后端仍会强制要求接口不是 running。
    if (!selectedConfigId || !selectedNodeId || !selectedConfig) return;
    if (!selectedConfigIsUnmanagedImport && !selectedNodeOnline) {
      throw new Error("Agent 离线，不能删除 WireGuard 配置");
    }
    if (!selectedConfigIsUnmanagedImport && !isConfigStopped) {
      throw new Error("删除前必须先断开对应 WireGuard 连接");
    }
    const confirmText = selectedConfigIsManagedLink
      ? `确认删除受管连接 ${selectedConfig.name} 及其对端配置？`
      : selectedConfigIsUnmanagedImport
        ? `确认删除导入观察记录 ${selectedConfig.name}？这不会删除节点上的 wg-quick 文件。`
        : `确认删除 WireGuard 配置 ${selectedConfig.name}？`;
    if (!window.confirm(confirmText)) return;
    if (selectedConfigIsManagedLink) {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}/managed-link`, { method: "DELETE" });
    } else {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}`, { method: "DELETE" });
    }
    setSelectedConfigId(null);
    setPlan(null);
    await refreshConfigs(selectedNodeId, null);
    await refreshImportCandidates(selectedNodeId);
    notify("success", selectedConfigIsManagedLink
      ? "受管连接双方配置已删除。"
      : selectedConfigIsUnmanagedImport
        ? "导入观察记录已删除，节点原始配置文件未改动。"
        : "WireGuard 配置已删除。");
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
      void pollImportScanTask(data.task_id, selectedNodeId);
    }
  }

  async function pollImportScanTask(taskId: number, nodeId: number) {
    try {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
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
    } catch (error) {
      notify("error", error instanceof Error ? error.message : String(error));
    }
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
          <h1>Link42</h1>
          <p className="muted">主控访问登录</p>
          <form className="stack" onSubmit={(event) => void runAction(() => login(event))}>
            <Field label="用户名">
              <input name="username" defaultValue={settingsUsername} autoComplete="username" required />
            </Field>
            <Field label="密码">
              <input name="password" type="password" autoComplete="current-password" required />
            </Field>
            <button type="submit"><Check size={16} /> 登录</button>
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
        <div>
          <h1>Link42</h1>
          <p>轻量 WireGuard 点对点链路管理 / {currentUser || "pmman"}</p>
        </div>
        <div className="topbarActions">
          <button className="iconButton" onClick={() => setSettingsOpen(true)} title="设置">
            <Settings size={18} />
          </button>
          <button className="iconButton" onClick={() => void runAction(refreshNodes)} title="刷新">
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
            <form className="stack" onSubmit={(event) => void runAction(() => saveSettings(event))}>
              <Field label="主控访问地址" hint="Agent 节点能访问到的 URL，例如 http://192.168.123.20:8000。">
                <input name="controller_url" defaultValue={controllerUrl} placeholder={DEFAULT_CONTROLLER_URL} required />
              </Field>
              <Field label="用户名">
                <input name="username" defaultValue={settingsUsername} required />
              </Field>
              <Field label="新密码" hint="留空表示不修改密码。">
                <input name="new_password" type="password" autoComplete="new-password" />
              </Field>
              <button type="submit"><Check size={16} /> 保存设置</button>
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
            <form onSubmit={(event) => void runAction(() => createNode(event))} className="gridForm">
              <Field label="节点名称" hint="用于在控制台识别这个 Agent。">
                <input name="name" placeholder="node-a" required />
              </Field>
              <Field label="主控地址" hint="Agent 安装时连接的 Link42 API 地址。">
                <input name="controller_url" placeholder="http://192.168.123.20:8000" defaultValue={controllerUrl} required />
              </Field>
              <Field label="入口地址" hint="多个地址用逗号分隔，后续受管连接会从这里选择 Endpoint。" wide>
                <textarea name="endpoint_ips" placeholder="203.0.113.10, 10.0.0.10" required />
              </Field>
              <button type="submit"><Plus size={16} /> 创建节点</button>
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
            <form key={`node-edit-${editingNode.id}`} onSubmit={(event) => void runAction(() => saveNode(event))} className="gridForm">
              <Field label="节点名称" hint="修改后会同步显示在节点列表。">
                <input name="name" placeholder="node-a" defaultValue={editingNode.name} required />
              </Field>
              <Field label="入口地址" hint="多个地址用逗号分隔；受管连接会校验所选地址属于节点。" wide>
                <textarea name="endpoint_ips" placeholder="203.0.113.10, 10.0.0.10" defaultValue={nodeEndpointOptions(editingNode).join(", ")} required />
              </Field>
              <button type="submit"><Check size={16} /> 保存节点</button>
            </form>
            <section className="modalSection">
              <h3>Agent token</h3>
              {editingNode.agent_token_value ? (
                <pre className="tokenBox">{editingNode.agent_token_value}</pre>
              ) : (
                <div className="empty">该节点创建时未保存明文 token，请轮换后查看。</div>
              )}
              <div className="empty">
                Agent {editingNode.agent_version || "未知版本"} / {String(editingNode.agent_platform?.service_manager || "未知服务管理器")}
                <br />
                {(editingNode.agent_capabilities || []).join(", ") || "尚未上报能力"}
              </div>
              <pre className="tokenBox">{buildAgentCommand(editingNode) || "轮换 token 后显示 Agent 启动命令。"}</pre>
              <div className="actionRow">
                <button className="secondary" onClick={() => void runAction(copyAgentCommand)}>复制启动命令</button>
                <button className="danger" onClick={() => void runAction(rotateNodeToken)}>轮换 token</button>
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
                      onClick={() => void runAction(() => refreshAgentUpgradePlan(editingNode.id))}
                    >
                      <RefreshCw size={16} /> 刷新升级计划
                    </button>
                    {agentUpgradePlan.upgrade_mode === "self_upgrade" ? (
                      <button onClick={() => void runAction(requestAgentUpgrade)}>
                        <Upload size={16} /> 一键升级
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
              <button className="danger" onClick={() => void runAction(deleteEditingNode)}>
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
              onSubmit={(event) => void runAction(() => saveConfig(event, "create"))}
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
	              <button type="submit" disabled={!selectedNodeOnline}><Plus size={16} /> 添加配置</button>
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
                <p className="muted">系统会为双方生成密钥，直接部署、启动，并启用 wg-quick 开机自启。</p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  setCreateDialog(null);
                  setManagedPeerNodeId(null);
                  setReplaceLocalConfigId(null);
                  setReplacePeerConfigId(null);
                  setForceEndpointMismatch(false);
                }}
              >
                <X size={18} />
              </button>
            </header>
            <form
              key={`create-managed-link-modal-${selectedNode.id}`}
              onSubmit={(event) => void runAction(() => createManagedLink(event))}
              className="gridForm describedForm"
            >
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
              <Field label="本端接口名称" hint="当前节点上创建的接口名。">
                <input name="local_interface_name" placeholder="wg-node-a" defaultValue={replaceLocalConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端接口名称" hint="对端节点上创建的接口名；同机双 Agent 测试时必须不同。">
                <input name="peer_interface_name" placeholder="wg-node-b" defaultValue={replacePeerConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端入口地址" hint="对端连接本节点时使用的 Endpoint 地址。">
                <EndpointSelect
                  key={`managed-local-endpoint-${replacePeerConfigId || "none"}-${managedLocalEndpointDefault}`}
                  name="local_endpoint_host"
                  defaultValue={managedLocalEndpointDefault}
                  placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                  options={managedLocalEndpointOptions}
                  disabled={!selectedNodeOnline}
                  locked={udp2rawEnabled}
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
                  locked={udp2rawEnabled}
                />
              </Field>
              <Field label="本端隧道 IP" hint="CIDR 格式，例如 10.42.0.1/32。">
                <input name="local_tunnel_ips" placeholder="10.42.0.1/32, fd42::1/64" defaultValue={replaceLocalConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端隧道 IP" hint="CIDR 格式，例如 10.42.0.2/32。">
                <input name="peer_tunnel_ips" placeholder="10.42.0.2/32, fd42::2/64" defaultValue={replacePeerConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
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
              <Field label="本端监听端口" hint="可选；留空表示不写 ListenPort。">
                <input name="local_listen_port" placeholder="51820" defaultValue={replaceLocalConfig?.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端监听端口" hint="可选；留空表示不写 ListenPort。">
                <input name="peer_listen_port" placeholder="51821" defaultValue={replacePeerConfig?.listen_port || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Udp2RawFields
                enabled={udp2rawEnabled}
                serverSide={udp2rawServerSide}
                disabled={!selectedNodeOnline}
                onEnabledChange={setUdp2rawEnabled}
                onServerSideChange={setUdp2rawServerSide}
              />
              <Field label="MTU" hint="双方链路 MTU，默认 1420。">
                <input name="mtu" placeholder="1420" defaultValue={replaceLocalConfig?.mtu || replacePeerConfig?.mtu || 1420} inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                <RouteModeSelect defaultValue={replaceLocalConfig?.table_name || replacePeerConfig?.table_name || ""} disabled={!selectedNodeOnline} />
              </Field>
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
                disabled={!selectedNodeOnline || selectedPeerNodeOptions.length === 0 || Boolean(replaceLocalConfigId && !replacePeerConfigId)}
              >
                <GitBranch size={16} /> 创建并启动双方连接
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

        <div className="nodeList">
          {nodes.map((node) => {
            const expanded = node.id === selectedNodeId;
            const online = isNodeSelectable(node);
            return (
              <section key={node.id} className={expanded ? "nodeCard expanded" : "nodeCard"}>
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
                          onClick={() => {
                            setManagedPeerNodeId(null);
                            setReplaceLocalConfigId(null);
                            setReplacePeerConfigId(null);
                            setForceEndpointMismatch(false);
                            setCreateDialog("managed");
                          }}
                        >
                          <GitBranch size={16} /> 创建受管连接
                        </button>
                      </div>
                    </section>

                    <div className="sectionActions">
                      <button
                        className="secondary"
                        disabled={!selectedNodeOnline}
                        onClick={() => void runAction(requestImportScan)}
                      >
                        <Upload size={16} /> 扫描现有 wg-quick
                      </button>
                    </div>

                    {importCandidates.length > 0 && (
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
                              disabled={candidate.imported || !selectedNodeOnline}
                              onClick={() => void runAction(() => importCandidate(candidate.id))}
                            >
                              {candidate.imported ? "已导入" : "导入"}
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
                            <span className={`statusBadge ${item.runtime_status === "running" ? "online" : ""}`}>
                              {statusLabel(item.runtime_status)}
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
                  onSubmit={(event) => void runAction(() => saveManagedLink(event))}
                  className="gridForm describedForm"
                >
                  <Field label="本端接口名称" hint={`当前节点：${selectedNode.name}`}>
                    <input name="local_interface_name" defaultValue={managedLink.local_interface.name} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="对端接口名称" hint={`对端节点：${selectedManagedLinkPeerNode?.name || managedLink.peer_interface.node_id}`}>
                    <input name="peer_interface_name" defaultValue={managedLink.peer_interface.name} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="本端隧道地址" hint="支持多个地址，例如 IPv4 + IPv6，用逗号分隔。">
                    <input name="local_tunnel_ips" defaultValue={managedLink.local_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="对端隧道地址" hint="支持多个地址，例如 IPv4 + IPv6，用逗号分隔。">
                    <input name="peer_tunnel_ips" defaultValue={managedLink.peer_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="本端 Peer AllowedIPs" hint="写入当前节点 [Peer]，用于声明可经对端到达的地址段。">
                    <input name="local_allowed_ips" defaultValue={managedLink.local_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="对端 Peer AllowedIPs" hint="写入对端节点 [Peer]，用于声明可经本端到达的地址段。">
                    <input name="peer_allowed_ips" defaultValue={managedLink.peer_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="本端入口地址" hint="对端连接本节点时使用。">
                    <EndpointSelect
                      key={`edit-local-endpoint-${managedLink.peer_peer.endpoint_host || ""}`}
                      name="local_endpoint_host"
                      defaultValue={managedLink.peer_peer.endpoint_host || ""}
                      placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                      options={editLocalEndpointOptions}
                      disabled={!selectedNodeOnline}
                      locked={udp2rawEnabled}
                    />
                  </Field>
                  <Field label="对端入口地址" hint="本端连接对端节点时使用。">
                    <EndpointSelect
                      key={`edit-peer-endpoint-${managedLink.local_peer.endpoint_host || ""}`}
                      name="peer_endpoint_host"
                      defaultValue={managedLink.local_peer.endpoint_host || ""}
                      placeholder={selectedManagedLinkPeerEndpoints[0] || "203.0.113.20"}
                      options={editPeerEndpointOptions}
                      disabled={!selectedNodeOnline}
                      locked={udp2rawEnabled}
                    />
                  </Field>
                  <Field label="本端监听端口" hint="可选；留空表示不写 ListenPort。">
                    <input name="local_listen_port" defaultValue={managedLink.local_interface.listen_port || ""} disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="对端监听端口" hint="可选；留空表示不写 ListenPort。">
                    <input name="peer_listen_port" defaultValue={managedLink.peer_interface.listen_port || ""} disabled={!selectedNodeOnline} />
                  </Field>
                  <Udp2RawFields
                    enabled={udp2rawEnabled}
                    serverSide={udp2rawServerSide}
                    defaults={managedLink.middleware}
                    disabled={!selectedNodeOnline}
                    onEnabledChange={setUdp2rawEnabled}
                    onServerSideChange={setUdp2rawServerSide}
                  />
                  <Field label="MTU" hint="双方链路 MTU，默认 1420。">
                    <input name="mtu" defaultValue={managedLink.local_interface.mtu || managedLink.peer_interface.mtu || 1420} disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                    <RouteModeSelect defaultValue={managedLink.local_interface.table_name || ""} disabled={!selectedNodeOnline} />
                  </Field>
                  <Field label="PersistentKeepalive" hint="双方 Peer 共用；常用 25。">
                    <input name="persistent_keepalive" placeholder="25" defaultValue={managedLink.local_peer.persistent_keepalive || ""} disabled={!selectedNodeOnline} />
                  </Field>
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
                  <button type="submit" disabled={!selectedNodeOnline}><Check size={16} /> 保存并下发双方配置</button>
                </form>
              </section>
            ) : (
              <>
                <section className="modalSection">
                  <h3>WireGuard 配置</h3>
                  <form
                    key={`edit-${selectedConfig.id}`}
                    onSubmit={(event) => void runAction(() => saveConfig(event, "update"))}
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
                    <button type="submit" disabled={!selectedNodeOnline}><Check size={16} /> 保存配置修改</button>
                  </form>
                </section>

                <section className="modalSection">
                  <h3>唯一对端</h3>
                  <form
                    key={`${selectedConfigId || "none"}-${peer?.id || "new"}`}
                    onSubmit={(event) => void runAction(() => savePeer(event))}
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
                    <button type="submit" disabled={!selectedNodeOnline}><Check size={16} /> 保存唯一对端</button>
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
                      <button className="secondary" disabled={!selectedNodeOnline} onClick={() => void runAction(takeOverConfig)}>
                        <Upload size={16} /> 接管导入配置
                      </button>
                      <button
                        className="secondary"
                        disabled={!selectedNodeOnline}
                        onClick={() => {
                          setReplaceLocalConfigId(selectedConfig.id);
                          setReplacePeerConfigId(null);
                          setManagedPeerNodeId(null);
                          setForceEndpointMismatch(false);
                          setSelectedConfigId(null);
                          setPlan(null);
                          setCreateDialog("managed");
                        }}
                      >
                        <GitBranch size={16} /> 导入为受管连接
                      </button>
                    </>
                  )}
                  {!selectedConfigIsUnmanagedImport && (
                    <button disabled={!selectedNodeOnline} onClick={() => void runAction(createApplyPlan)}>
                      <GitBranch size={16} /> 生成部署计划
                    </button>
                  )}
                </>
              )}
              {selectedConfigIsManagedLink && (
                <div className="empty">受管连接由系统直接管理，保存修改会立即下发双方配置，不需要生成部署计划。</div>
              )}
              <div className="actionRow">
                {!selectedConfigIsManagedLink && !selectedConfigIsUnmanagedImport && (
                  <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy} onClick={() => void runAction(refreshDeployedConfig)}>
                    <RefreshCw size={16} /> 同步节点配置
                  </button>
                )}
                {!selectedConfigIsUnmanagedImport && (
                  <>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigRunning} onClick={() => void runAction(startSelectedConfig)}>
                      {selectedConfig.runtime_status === "starting" ? "启动中" : selectedConfigIsManagedLink ? "启动双方连接" : "启动连接"}
                    </button>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigStopped} onClick={() => void runAction(stopSelectedConfig)}>
                      {selectedConfig.runtime_status === "stopping" ? "断开中" : selectedConfigIsManagedLink ? "断开双方连接" : "断开连接"}
                    </button>
                  </>
                )}
                <button className="danger" disabled={selectedConfigIsUnmanagedImport ? false : (!selectedNodeOnline || isConfigBusy || !isConfigStopped)} onClick={() => void runAction(deleteSelectedConfig)}>
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
                  <button disabled={!selectedNodeOnline || plan.status !== "draft" || !hasDeployDiff} onClick={() => void runAction(confirmPlan)}>
                    <Check size={16} /> 确认执行
                  </button>
                </div>
              )}
            </section>
          </section>
        </div>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
