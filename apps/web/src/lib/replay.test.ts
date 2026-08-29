import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchPublicReplay } from "./replay";

describe("fetchPublicReplay", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns the parsed replay on 200", async () => {
    const payload = { slug: "abc123def456", title: "T", case_id: "INC-1", snapshot: { stepCount: 3 }, view_count: 5, created_at: "x" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } })),
    );
    const result = await fetchPublicReplay("abc123def456");
    expect(result?.slug).toBe("abc123def456");
    expect(result?.snapshot.stepCount).toBe(3);
  });

  it("returns null on 404", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 404 })));
    expect(await fetchPublicReplay("missing")).toBeNull();
  });

  it("returns null on network error (never throws)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("boom");
      }),
    );
    expect(await fetchPublicReplay("x")).toBeNull();
  });

  it("URL-encodes the slug", async () => {
    const spy = vi.fn(async (_url: string) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", spy);
    await fetchPublicReplay("a/b");
    expect(String(spy.mock.calls[0]?.[0])).toContain("a%2Fb");
  });
});
