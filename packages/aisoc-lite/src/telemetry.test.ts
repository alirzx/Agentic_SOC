import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveTelemetry, buildPayload } from "./telemetry.js";
import { triageBatch } from "./verdict/engine.js";
import { loadDemoAlerts } from "./fixtures/index.js";

describe("resolveTelemetry — opt-in only", () => {
  const original = process.env.AISOC_TELEMETRY;
  beforeEach(() => {
    delete process.env.AISOC_TELEMETRY;
  });
  afterEach(() => {
    if (original === undefined) delete process.env.AISOC_TELEMETRY;
    else process.env.AISOC_TELEMETRY = original;
  });

  it("defaults to OFF", () => {
    expect(resolveTelemetry({}).enabled).toBe(false);
  });

  it("--no-telemetry beats everything", () => {
    process.env.AISOC_TELEMETRY = "1";
    expect(resolveTelemetry({ telemetry: true, noTelemetry: true }).enabled).toBe(false);
  });

  it("--telemetry opts in", () => {
    expect(resolveTelemetry({ telemetry: true }).enabled).toBe(true);
  });

  it("env AISOC_TELEMETRY=1 opts in; =0 opts out", () => {
    process.env.AISOC_TELEMETRY = "1";
    expect(resolveTelemetry({}).enabled).toBe(true);
    process.env.AISOC_TELEMETRY = "0";
    expect(resolveTelemetry({}).enabled).toBe(false);
  });
});

describe("buildPayload — aggregate only, no alert content", () => {
  it("contains only counts and metadata", () => {
    const result = triageBatch(loadDemoAlerts());
    const payload = buildPayload(result, "demo", "0.1.0");
    const serialized = JSON.stringify(payload);
    // No alert titles, IOCs, hostnames, or raw text may appear.
    expect(serialized).not.toMatch(/ransomware|WIN-|mimikatz|\d+\.\d+\.\d+\.\d+/);
    expect(payload).toMatchObject({ event: "triage", total: 200, source: "demo" });
    expect(Object.keys(payload).sort()).toEqual(
      ["deterministic", "elapsedMs", "event", "needsReview", "source", "suppressed", "total", "truePositive", "version"].sort(),
    );
  });
});
