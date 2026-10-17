// Strict reading of wire records (§1, §8 steps 1–2). Writers build plain objects directly.
import { malformed, unsupported } from "../errors.js";
import { utf8 } from "../internal/bytes.js";
import { fromBase64url, toBase64url } from "./base64url.js";

export type JsonRecord = { readonly [key: string]: unknown };

/** Protocol bounds (§2, D-18). */
export const LIMITS = { idBytes: 128, parts: 128, meta: 4096, owners: 64 } as const;

const MAX_U32 = 0xffff_ffff;

/** Reads the fields of one JSON object; refuses missing, unknown and mistyped fields. */
export class Fields {
  readonly #object: JsonRecord;

  private constructor(object: JsonRecord) {
    this.#object = object;
  }

  /** `required` must all be present; `optional` may be; nothing else. */
  static of(json: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
    if (typeof json !== "object" || json === null || Array.isArray(json)) throw malformed();
    const object = json as JsonRecord;
    for (const key of required) if (!Object.hasOwn(object, key)) throw malformed();
    for (const key of Object.keys(object)) {
      if (!required.includes(key) && !optional.includes(key)) throw malformed();
    }
    return new Fields(object);
  }

  has(key: string): boolean {
    return Object.hasOwn(this.#object, key);
  }

  #get(key: string): unknown {
    if (!this.has(key)) throw malformed();
    return this.#object[key];
  }

  /** An opaque id (§1): UTF-8, 1–128 bytes, no NUL. */
  id(key: string): string {
    return checkId(this.#get(key));
  }

  literal<T extends string>(key: string, values: readonly T[]): T {
    const value = this.#get(key);
    if (!values.includes(value as T)) throw malformed();
    return value as T;
  }

  int(key: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
    const value = this.#get(key);
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) throw malformed();
    return value;
  }

  u32(key: string, min = 0): number {
    return this.int(key, min, MAX_U32);
  }

  bytes(key: string, length: number): Uint8Array {
    return fromBase64url(this.#get(key) as string, length);
  }

  bytesUpTo(key: string, min: number, max: number): Uint8Array {
    const value = fromBase64url(this.#get(key) as string);
    if (value.length < min || value.length > max) throw malformed();
    return value;
  }

  /** A library-chosen id: base64url of 16 random bytes (§1). */
  randomId(key: string): string {
    const value = this.#get(key) as string;
    fromBase64url(value, 16);
    return value;
  }

  object(key: string, required: readonly string[], optional?: readonly string[]): Fields {
    return Fields.of(this.#get(key), required, optional);
  }

  nullable<T>(key: string, read: (fields: Fields, key: string) => T): T | null {
    return this.#get(key) === null ? null : read(this, key);
  }

  list<T>(key: string, min: number, max: number, read: (item: unknown) => T): T[] {
    const value = this.#get(key);
    if (!Array.isArray(value) || value.length < min || value.length > max) throw malformed();
    return value.map(read);
  }
}

export function checkId(value: unknown): string {
  if (typeof value !== "string" || value.includes("\0")) throw malformed();
  const length = utf8(value).length;
  if (length < 1 || length > LIMITS.idBytes) throw malformed();
  return value;
}

/** §8 steps 1–2: envelope shape, then a supported `v`. The suite is resolved by the caller. */
export function readEnvelope(json: unknown, type: string, versions: readonly number[]): { v: number; suite: string } {
  if (typeof json !== "object" || json === null || Array.isArray(json)) throw malformed();
  const { v, suite, type: actual } = json as JsonRecord;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || typeof suite !== "string" || actual !== type) {
    throw malformed();
  }
  if (!versions.includes(v)) throw unsupported();
  return { v, suite };
}

export const b64 = toBase64url;
