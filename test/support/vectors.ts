import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytes, list, optional, string, u32, u64, u8, type Field } from "../../src/encoding/canonical.js";
import type { Suite } from "../../src/suites/suite.js";

const DIR = join(import.meta.dirname, "..", "vectors");

export const loadVectors = <T>(file: string): T => JSON.parse(readFileSync(join(DIR, file), "utf8")) as T;
export const loadAttachment = (file: string) => new Uint8Array(readFileSync(join(DIR, file)));

export const unhex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
export const tohex = (value: Uint8Array) => Buffer.from(value).toString("hex");

/** A vector field `[type, value]`, encoded by the library's own encoder. */
export type VectorField = [string, unknown];

export function toField([type, value]: VectorField): Field {
  switch (type) {
    case "u8":
      return u8(value as number);
    case "u32":
      return u32(value as number);
    case "u64":
      return u64(value as number);
    case "bytes":
      return bytes(unhex(value as string));
    case "string":
      return string(value as string);
    case "raw":
      return unhex(value as string);
    case "optional":
      return optional(value as VectorField | null, (inner) => toField(inner));
    case "list":
      return list(value as VectorField[][], (item) => new Uint8Array(Buffer.concat(item.map(toField))));
    default:
      throw new Error(`unknown vector field type ${type}`);
  }
}

/** A suite whose random values are fixed, to replay deterministic vectors. */
export function withRandom(suite: Suite, ...values: Uint8Array[]): Suite {
  const queue = [...values];
  return {
    ...suite,
    randomBytes(length) {
      const next = queue.shift();
      if (!next || next.length !== length) throw new Error("unexpected random draw");
      return next;
    },
  };
}
