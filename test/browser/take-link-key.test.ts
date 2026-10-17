/** takeLinkKey (§3.5, D-22): the fragment is read, validated, and removed from the address bar and history. */
import { describe, expect, it } from "vitest";
import { takeLinkKey } from "../../src/browser/index.js";

function browser(url: string) {
  const calls: unknown[][] = [];
  const location = { href: url, hash: url.includes("#") ? url.slice(url.indexOf("#")) : "" };
  const history = { state: { page: 1 }, replaceState: (...args: unknown[]) => void calls.push(args) };
  return { location, history, calls };
}
const key = "1" + Buffer.alloc(32, 5).toString("base64url");

describe("takeLinkKey", () => {
  it("returns the key and removes the fragment, keeping the history state", () => {
    const b = browser(`https://app.example/s/team-1/item-1#${key}`);
    expect(takeLinkKey(b)).toBe(key);
    expect(b.calls).toEqual([[{ page: 1 }, "", "https://app.example/s/team-1/item-1"]]);
  });

  it.each([
    ["an unknown prefix", "2" + key.slice(1), "UNSUPPORTED_VERSION"],
    ["a short key", "1abc", "MALFORMED_RECORD"],
  ])("removes the fragment even for %s", (_, value, code) => {
    const b = browser(`https://app.example/s#${value}`);
    expect(() => takeLinkKey(b)).toThrow(expect.objectContaining({ code }));
    expect(b.calls).toHaveLength(1);
  });

  it("returns null and touches nothing without a fragment", () => {
    const b = browser("https://app.example/s");
    expect(takeLinkKey(b)).toBeNull();
    expect(b.calls).toEqual([]);
  });
});
