// The two lists of protocol §2, compared with bit 255 cleared.
const fromHex = (value: string) => Uint8Array.from(value.match(/../g)!, (byte) => parseInt(byte, 16));

const ZERO = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE = "0100000000000000000000000000000000000000000000000000000000000000";
const P_MINUS_1 = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
const P = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
const P_PLUS_1 = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

export const ED25519_SMALL_ORDER = [
  ZERO,
  ONE,
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  P_MINUS_1,
  P,
  P_PLUS_1,
].map(fromHex);

export const X25519_LOW_ORDER = [
  ZERO,
  ONE,
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  P_MINUS_1,
  P,
  P_PLUS_1,
].map(fromHex);

/** Constant-time over the list: the input may be a secret-derived value. */
export function inList(list: readonly Uint8Array[], value: Uint8Array): boolean {
  if (value.length !== 32) return false;
  let found = 0;
  for (const entry of list) {
    let diff = (value[31]! & 0x7f) ^ entry[31]!;
    for (let i = 0; i < 31; i++) diff |= value[i]! ^ entry[i]!;
    found |= Number(diff === 0);
  }
  return found === 1;
}

// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L = fromHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

/** S < L (§2): a signature's S must be canonical. */
export function isCanonicalScalar(s: Uint8Array): boolean {
  if (s.length !== 32) return false;
  for (let i = 31; i >= 0; i--) {
    if (s[i]! < L[i]!) return true;
    if (s[i]! > L[i]!) return false;
  }
  return false;
}
