/**
 * SP-17: Unknown versions and algorithms are refused.
 * Threats: TH-24.
 */
import { describe, expect, it } from "vitest";
import { decodeAnchor, decodeLinkKey } from "../../src/encoding/link.js";
import { suiteFor } from "../../src/suites/registry.js";

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
