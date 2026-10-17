// Canonical binary encoding (§1): the only input to signatures, hashes, AD and derivations.
import { malformed } from "../errors.js";
import { concat, fromUtf8, utf8 } from "../internal/bytes.js";

/** One encoded field. `enc` concatenates them in order. */
export type Field = Uint8Array;

const MAX_U32 = 0xffff_ffff;

export function u8(value: number): Field {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) throw malformed();
  return Uint8Array.of(value);
}

export function u32(value: number): Field {
  if (!Number.isInteger(value) || value < 0 || value > MAX_U32) throw malformed();
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

/** JSON integers fit in 53 bits (§1), so a u64 is a safe integer. */
export function u64(value: number): Field {
  if (!Number.isSafeInteger(value) || value < 0) throw malformed();
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

export function bytes(value: Uint8Array): Field {
  return concat(u32(value.length), value);
}

export function string(value: string): Field {
  return bytes(utf8(value));
}

export function list<T>(items: readonly T[], encodeItem: (item: T) => Field): Field {
  return concat(u32(items.length), ...items.map(encodeItem));
}

export function optional<T>(value: T | null | undefined, encodeValue: (value: T) => Field): Field {
  return value === null || value === undefined ? u8(0) : concat(u8(1), encodeValue(value));
}

export function enc(...fields: readonly Field[]): Uint8Array {
  return concat(...fields);
}

/** Reads a canonical encoding; every overrun or leftover byte is `MALFORMED_RECORD`. */
export class Reader {
  #offset = 0;
  constructor(private readonly input: Uint8Array) {}

  #take(length: number): Uint8Array {
    if (length > this.input.length - this.#offset) throw malformed();
    const out = this.input.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return out;
  }

  u8(): number {
    return this.#take(1)[0]!;
  }

  u32(): number {
    const view = this.#take(4);
    return new DataView(view.buffer, view.byteOffset).getUint32(0);
  }

  u64(): number {
    const view = this.#take(8);
    const value = new DataView(view.buffer, view.byteOffset).getBigUint64(0);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw malformed();
    return Number(value);
  }

  bytes(): Uint8Array {
    return this.#take(this.u32()).slice();
  }

  string(): string {
    return fromUtf8(this.#take(this.u32()));
  }

  list<T>(readItem: (reader: Reader) => T, max = MAX_U32): T[] {
    const count = this.u32();
    if (count > max) throw malformed();
    const items: T[] = [];
    for (let i = 0; i < count; i++) items.push(readItem(this));
    return items;
  }

  optional<T>(readValue: (reader: Reader) => T): T | null {
    const flag = this.u8();
    if (flag === 0) return null;
    if (flag !== 1) throw malformed();
    return readValue(this);
  }

  /** Refuses trailing bytes. */
  end(): void {
    if (this.#offset !== this.input.length) throw malformed();
  }
}
