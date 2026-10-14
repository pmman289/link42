import { describe, expect, it } from "vitest";
import { replaceIPv4 } from "./ipam";

describe("IPv4 表单推荐", () => {
  it("替换现有 IPv4 时保留多条 IPv6 地址", () => {
    expect(replaceIPv4("10.0.0.1/24, fd42::1/64\n2001:db8::1/128", ["10.1.0.1/30"]))
      .toBe("10.1.0.1/30, fd42::1/64, 2001:db8::1/128");
  });
  it("可以填入固定地址和 /31 链路地址", () => {
    expect(replaceIPv4("", ["10.0.0.0/31"])).toBe("10.0.0.0/31");
    expect(replaceIPv4("10.0.0.1/30", ["10.2.0.1/32"])).toBe("10.2.0.1/32");
  });
});
