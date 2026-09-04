export type TopologyTone = "healthy" | "warning" | "critical" | "inactive" | "unknown";

export type TopologyMonitorSummary = {
  last_latency_ms: number | null;
  packet_loss: number;
  sample_count: number;
};

export type TopologyStateEdge = {
  local_status: string;
  peer_status: string;
  local_monitor: TopologyMonitorSummary | null;
  peer_monitor: TopologyMonitorSummary | null;
};

export type TopologyStateDisplayEdge = TopologyStateEdge & {
  link_count: number;
  links: TopologyStateEdge[];
};

/** 计算单条拓扑链路的健康状态。 */
export function topologySingleEdgeTone(edge: TopologyStateEdge): TopologyTone {
  if ([edge.local_status, edge.peer_status].every((status) => status === "stopped" || status === "stopping")) {
    return "inactive";
  }

  const summaries = [edge.local_monitor, edge.peer_monitor].filter(
    (summary): summary is TopologyMonitorSummary => summary !== null,
  );
  const sampledSummaries = summaries.filter((summary) => summary.sample_count > 0);
  if (sampledSummaries.length === 0) return "unknown";

  // 只有所有已有样本的监测方向最近一次都失败时，才把线路视为真正断开。
  const hasReachableSample = sampledSummaries.some((summary) => typeof summary.last_latency_ms === "number");
  if (!hasReachableSample) return "critical";

  // 历史丢包和高延迟说明线路质量下降，但当前仍可达，因此显示为黄色告警。
  if (
    sampledSummaries.some(
      (summary) => summary.packet_loss > 0 || (typeof summary.last_latency_ms === "number" && summary.last_latency_ms > 300),
    )
  ) {
    return "warning";
  }
  return "healthy";
}

/** 返回用于拓扑状态和监测摘要的链路，主动关闭或完全不可达链路不污染可用链路数据。 */
export function topologyOperationalLinks(edge: TopologyStateDisplayEdge): TopologyStateEdge[] {
  const activeLinks = edge.links.filter((link) => topologySingleEdgeTone(link) !== "inactive");
  if (activeLinks.length === 0) return edge.links;

  const usableLinks = activeLinks.filter((link) => topologySingleEdgeTone(link) !== "critical");
  return usableLinks.length > 0 ? usableLinks : activeLinks;
}

/** 汇总多条合并链路后的拓扑健康状态，并优先保留仍可用的链路状态。 */
export function topologyEdgeTone(edge: TopologyStateDisplayEdge): TopologyTone {
  const tones = edge.links.map(topologySingleEdgeTone).filter((tone) => tone !== "inactive");
  if (tones.length === 0) return "inactive";
  if (tones.includes("warning")) return "warning";
  if (tones.includes("healthy")) return "healthy";
  if (tones.every((tone) => tone === "critical")) return "critical";
  return "unknown";
}

/** 计算数值列表平均值，空列表返回 null。 */
function average(values: number[]): number | null {
  if (values.length === 0) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

/** 格式化延迟标签，缺少可达样本时显示占位符。 */
function formatLatency(value: number | null): string {
  return typeof value === "number" ? `${Math.round(value)}ms` : "--";
}

/** 格式化丢包标签，缺少监测样本时显示占位符。 */
function formatLoss(value: number | null): string {
  return typeof value === "number" ? `${(value * 100).toFixed(value > 0.01 ? 1 : 0)}%` : "--";
}

/** 生成合并拓扑边的延迟和丢包摘要，忽略完全不可达的备用链路。 */
export function topologyEdgeSummary(edge: TopologyStateDisplayEdge): string {
  if (topologyEdgeTone(edge) === "inactive") return `${edge.link_count > 1 ? `${edge.link_count}条链路 · ` : ""}-- / --`;

  const summaries = topologyOperationalLinks(edge)
    .flatMap((link) => [link.local_monitor, link.peer_monitor])
    .filter((summary): summary is TopologyMonitorSummary => summary !== null && summary.sample_count > 0);
  const prefix = edge.link_count > 1 ? `${edge.link_count}条链路 · ` : "";
  if (summaries.length === 0) return `${prefix}-- / --`;

  const latencies = summaries
    .map((summary) => summary.last_latency_ms)
    .filter((value): value is number => typeof value === "number");
  const losses = summaries.map((summary) => summary.packet_loss);
  return `${prefix}${formatLatency(average(latencies))} / ${formatLoss(average(losses))}`;
}
