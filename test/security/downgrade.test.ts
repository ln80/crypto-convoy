/**
 * SP-17: Unknown versions and algorithms are refused.
 * Threats: TH-24.
 */
import { describe, expect, it, vi } from "vitest";
import { decodeAnchor, decodeLinkKey } from "../../src/encoding/link.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { suiteFor } from "../../src/suites/registry.js";
import { parsers } from "../support/parsers.js";
import { sampleRecords } from "../support/records.js";

const unsupported = expect.objectContaining({ code: "UNSUPPORTED_VERSION" });
const key = "1" + Buffer.alloc(32, 9).toString("base64url");

describe("SP-17: unknown suites and link formats are refused", () => {
  it.each(["cc0", "cc2", "CC1", "", " cc1", undefined, null, 1])("refuses suite %j before any crypto", (id) => {
    expect(() => suiteFor(id)).toThrow(unsupported);
  });

  it.each(["0", "2", "9", "a", "-"])("refuses link prefix %s", (prefix) => {
    expect(() => decodeLinkKey(prefix + key.slice(1))).toThrow(unsupported);
    expect(() => decodeAnchor(prefix + key.slice(1))).toThrow(unsupported);
  });
});

describe("SP-17: every record type refuses unknown versions and suites before any crypto", () => {
  const sample = sampleRecords();
  const parse = parsers(sample.submissionId);
  const crypto = ["verify", "aeadDecrypt", "sealOpen", "hash", "keyedHash", "streamPull"] as const;

  for (const [type, json] of Object.entries(sample.records)) {
    it.each([
      ["v 2", { v: 2 }],
      ["v 0", { v: 0 }],
      ["suite cc2", { suite: "cc2" }],
      ["suite in another case", { suite: "CC1" }],
    ])(`${type}: refuses %s`, (_, change) => {
      const spies = crypto.map((name) => vi.spyOn(cc1, name));
      expect(() => parse[type as keyof typeof parse]({ ...json, ...change })).toThrow(unsupported);
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    });
  }
});
