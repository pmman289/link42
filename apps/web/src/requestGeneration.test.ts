import { describe, expect, it } from "vitest";
import { RequestGeneration, StaleRequestError } from "./requestGeneration";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe("request ownership", () => {
  it("rejects an old token response while accepting a new session response", async () => {
    const scope = new RequestGeneration();
    const old = deferred<string>();
    const pending = scope.run(() => old.promise);
    const rejected = expect(pending).rejects.toBeInstanceOf(StaleRequestError);
    scope.invalidate();
    expect(await scope.run(async () => "new token")).toBe("new token");
    old.resolve("old token");
    await rejected;
  });

  it("does not let a delayed 401 expire the new session", async () => {
    const scope = new RequestGeneration();
    const response = deferred<number>();
    let expired = false;
    const pending = scope.run(async (assertCurrent) => {
      const status = await response.promise;
      assertCurrent();
      if (status === 401) expired = true;
    });
    const rejected = expect(pending).rejects.toBeInstanceOf(StaleRequestError);
    scope.invalidate();
    response.resolve(401);
    await rejected;
    expect(expired).toBe(false);
  });

  it("discards an old network failure but preserves failures in the current session", async () => {
    const scope = new RequestGeneration();
    const old = deferred<void>();
    const pending = scope.run(() => old.promise);
    const rejected = expect(pending).rejects.toBeInstanceOf(StaleRequestError);
    scope.invalidate();
    old.reject(new Error("connection lost"));
    await rejected;
    const error = new Error("current failure");
    await expect(scope.run(async () => { throw error; })).rejects.toBe(error);
  });

  it("invalidates a response still parsing its body", async () => {
    const scope = new RequestGeneration();
    const body = deferred<object>();
    const pending = scope.run(() => body.promise);
    const rejected = expect(pending).rejects.toBeInstanceOf(StaleRequestError);
    scope.invalidate();
    body.resolve({ secret: "previous account" });
    await rejected;
  });
});
