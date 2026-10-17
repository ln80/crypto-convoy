// recovery-key.v1.json: BIP-39 seed (PBKDF2 from node:crypto, independent of @scure/bip39) and recovery key (§5.2).
import { pbkdf2Sync } from "node:crypto";
import { encode, hex, label, sodium, writeVectors } from "./common.mjs";

const seedOf = (phrase) => new Uint8Array(pbkdf2Sync(Buffer.from(phrase.normalize("NFKD")), "mnemonic", 2048, 64, "sha512"));
const cases = [
  { entropy: "00000000000000000000000000000000", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow" },
].map(({ entropy, phrase }) => {
  const seed = seedOf(phrase);
  const accountId = "alice";
  return {
    entropy,
    phrase,
    accountId,
    seed: hex(seed),
    recoveryKey: hex(sodium.crypto_generichash(32, encode([label("recovery-key"), ["string", accountId]]), seed)),
  };
});

writeVectors("recovery-key.v1.json", {
  file: "recovery-key.v1",
  covers: "Protocol §5.2 recovery key: BIP-39 (English, 128-bit entropy, empty passphrase), keyed BLAKE2b",
  cases,
  refused: [
    { name: "bad checksum", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", error: "WRONG_CREDENTIAL" },
    { name: "11 words", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", error: "WRONG_CREDENTIAL" },
    { name: "word not in the list", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abacus", error: "WRONG_CREDENTIAL" },
  ],
});
