import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { buildApp } from "./app.js";

// GHSA-mrhx-c7xc-m3w5 is fixed in zod 4.6.6; anything older is vulnerable.
const FIXED_ZOD_VERSION = "4.6.6";

function semverParts(value: string): [number, number, number] {
  const match = value.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) throw new Error(`no semver found in ${JSON.stringify(value)}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function isAtLeast(version: string, minimum: string): boolean {
  const actual = semverParts(version);
  const required = semverParts(minimum);
  for (let i = 0; i < 3; i++) {
    if (actual[i] !== required[i]) return actual[i] > required[i];
  }
  return true;
}

describe("zod CVE bump (GHSA-mrhx-c7xc-m3w5)", () => {
  test("manifest and lockfile resolve zod to the fixed version", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    );
    const lockfile = JSON.parse(
      readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"),
    );
    expect(isAtLeast(manifest.dependencies.zod, FIXED_ZOD_VERSION)).toBe(true);
    expect(
      isAtLeast(lockfile.packages["node_modules/zod"].version, FIXED_ZOD_VERSION),
    ).toBe(true);
  });

  test("POST /api/projects still validates and strips unknown keys after the bump", async () => {
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/projects",
      payload: { name: "demo", config: { retries: 3, unexpected: "x" }, extra: 1 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ name: "demo", config: { retries: 3 } });
  });
});
