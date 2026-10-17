// Base64url without padding (§1): the one byte encoding of records and links.
import { malformed } from "../errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const VALUES = new Map([...ALPHABET].map((char, index) => [char, index]));

export function toBase64url(input: Uint8Array): string {
  let out = "";
  for (let i = 0; i < input.length; i += 3) {
    const chunk = (input[i]! << 16) | ((input[i + 1] ?? 0) << 8) | (input[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((input.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += ALPHABET[(chunk >> (18 - 6 * j)) & 63];
  }
  return out;
}

/**
 * Strict decoding: refuses padding, characters outside the alphabet and
 * non-zero trailing bits, so each byte string has exactly one encoding.
 */
export function fromBase64url(text: string, length?: number): Uint8Array {
  if (typeof text !== "string" || text.length % 4 === 1) throw malformed();
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of text) {
    const value = VALUES.get(char);
    if (value === undefined) throw malformed();
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) throw malformed();
  if (length !== undefined && out.length !== length) throw malformed();
  return out;
}
