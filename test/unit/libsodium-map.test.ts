/** docs/libsodium-map.md lists exactly the libsodium functions the suites call. */
import { describe, expect, it } from "vitest";
import { codeOnly, read, tsFiles } from "../support/source.js";

const used = new Set(
  tsFiles("src/suites").flatMap((file) =>
    [...codeOnly(read(file)).matchAll(/\bsodium\.([a-zA-Z0-9_]+)/g)].map((m) => m[1]!),
  ),
);

const listed = new Set(
  read("docs/libsodium-map.md")
    .split("## Other primitives")[0]!
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .flatMap((line) => [...line.split("|")[1]!.matchAll(/`([a-zA-Z0-9_]+)`/g)].map((m) => m[1]!)),
);

describe("libsodium map", () => {
  it.each([...used].sort())("%s is documented", (name) => expect(listed).toContain(name));
  it.each([...listed].sort())("%s is used by a suite", (name) => expect(used).toContain(name));
});
