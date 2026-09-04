import { describe, expect, it } from "vitest";
import {
  topologyEdgeSummary,
  topologyEdgeTone,
  topologyOperationalLinks,
  topologySingleEdgeTone,
  type TopologyStateDisplayEdge,
  type TopologyStateEdge,
} from "./topologyState";

/** 构造一条用于状态测试的拓扑链路。 */
function link(overrides: Partial<TopologyStateEdge> = {}): TopologyStateEdge {
  return {
    local_status: "running",
    peer_status: "running",
    local_monitor: {
      last_latency_ms: 195,
      packet_loss: 0,
      sample_count: 10,
    },
    peer_monitor: {
      last_latency_ms: 195,
      packet_loss: 0,
      sample_count: 10,
    },
    ...overrides,
  };
}

/** 构造一条包含多条物理连接的拓扑聚合边。 */
function displayEdge(links: TopologyStateEdge[]): TopologyStateDisplayEdge {
  return {
    ...links[0],
    link_count: links.length,
    links,
  };
}

describe("拓扑链路状态", () => {
  it("将当前可达且 195ms、0% 丢包的链路标记为健康", () => {
    expect(topologySingleEdgeTone(link())).toBe("healthy");
  });

  it("将当前可达但存在历史丢包的链路标记为告警", () => {
    expect(
      topologySingleEdgeTone(
        link({
          local_monitor: { last_latency_ms: 2, packet_loss: 0.0033, sample_count: 300 },
          peer_monitor: { last_latency_ms: 2, packet_loss: 0, sample_count: 300 },
        }),
      ),
    ).toBe("warning");
  });

  it("将当前可达但延迟超过 300ms 的链路标记为告警", () => {
    expect(
      topologySingleEdgeTone(
        link({
          local_monitor: { last_latency_ms: 301, packet_loss: 0, sample_count: 1 },
          peer_monitor: { last_latency_ms: 301, packet_loss: 0, sample_count: 1 },
        }),
      ),
    ).toBe("warning");
  });

  it("将没有样本的链路标记为未知", () => {
    expect(
      topologySingleEdgeTone(
        link({
          local_monitor: { last_latency_ms: null, packet_loss: 0, sample_count: 0 },
          peer_monitor: null,
        }),
      ),
    ).toBe("unknown");
  });

  it("只有所有有样本方向最近一次都失败时才标记为断开", () => {
    expect(
      topologySingleEdgeTone(
        link({
          local_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 4 },
          peer_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 4 },
        }),
      ),
    ).toBe("critical");
  });

  it("一端失败一端成功时保留为告警而不是断开", () => {
    expect(
      topologySingleEdgeTone(
        link({
          local_monitor: { last_latency_ms: null, packet_loss: 0.5, sample_count: 2 },
          peer_monitor: { last_latency_ms: 8, packet_loss: 0, sample_count: 2 },
        }),
      ),
    ).toBe("warning");
  });

  it("多链路中健康线路优先于完全失败线路", () => {
    const healthy = link();
    const failed = link({
      local_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 3 },
      peer_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 3 },
    });
    const edge = displayEdge([healthy, failed]);

    expect(topologyEdgeTone(edge)).toBe("healthy");
    expect(topologyOperationalLinks(edge)).toEqual([healthy]);
    expect(topologyEdgeSummary(edge)).toBe("2条链路 · 195ms / 0%");
  });

  it("多链路中告警线路优先于健康线路", () => {
    const healthy = link();
    const warning = link({
      local_monitor: { last_latency_ms: 301, packet_loss: 0, sample_count: 5 },
      peer_monitor: { last_latency_ms: 301, packet_loss: 0, sample_count: 5 },
    });
    const edge = displayEdge([healthy, warning]);

    expect(topologyEdgeTone(edge)).toBe("warning");
    expect(topologyOperationalLinks(edge)).toEqual([healthy, warning]);
  });

  it("多链路全部失败时标记为断开并保留失败摘要", () => {
    const failed = link({
      local_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 3 },
      peer_monitor: { last_latency_ms: null, packet_loss: 1, sample_count: 3 },
    });
    const edge = displayEdge([failed, { ...failed }]);

    expect(topologyEdgeTone(edge)).toBe("critical");
    expect(topologyOperationalLinks(edge)).toHaveLength(2);
    expect(topologyEdgeSummary(edge)).toBe("2条链路 · -- / 100.0%");
  });

  it("主动关闭的链路全部不存在时显示灰色状态", () => {
    const stopped = link({ local_status: "stopped", peer_status: "stopped" });
    const edge = displayEdge([stopped]);

    expect(topologyEdgeTone(edge)).toBe("inactive");
    expect(topologyEdgeSummary(edge)).toBe("-- / --");
  });
});
