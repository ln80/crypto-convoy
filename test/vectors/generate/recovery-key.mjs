// recovery-key.v1.json: BIP-39 seed (PBKDF2 from node:crypto, independent of @scure/bip39), recovery key,
// recovery signing key, and a recovery signature over member keys (§4.2, §5.2).
import { pbkdf2Sync } from "node:crypto";
import { encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

const seedOf = (phrase) => new Uint8Array(pbkdf2Sync(Buffer.from(phrase.normalize("NFKD")), "mnemonic", 2048, 64, "sha512"));
const cases = [
  { entropy: "00000000000000000000000000000000", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow" },
].map(({ entropy, phrase }) => {
  const seed = seedOf(phrase);
  const accountId = "alice";
  const signingSeed = sodium.crypto_generichash(32, encode([label("recovery-signing-key"), ["string", accountId]]), seed);
  return {
    entropy,
    phrase,
    accountId,
    seed: hex(seed),
    recoveryKey: hex(sodium.crypto_generichash(32, encode([label("recovery-key"), ["string", accountId]]), seed)),
    recoverySigningSeed: hex(signingSeed),
    recoveryPublicKey: hex(sodium.crypto_sign_seed_keypair(signingSeed).publicKey),
  };
});

// A re-key proven by the first case's recovery key (§4.2): Ed25519 signatures are deterministic.
const signer = sodium.crypto_sign_seed_keypair(Buffer.from(cases[0].recoverySigningSeed, "hex"));
const keys = {
  teamId: "team-1", accountId: "alice", memberKeysVersion: 2,
  signingPublicKey: hex(sodium.crypto_sign_seed_keypair(fixed("rekey signing seed", 32)).publicKey),
  encryptionPublicKey: hex(sodium.crypto_scalarmult_base(fixed("rekey encryption secret", 32))),
  recoveryPublicKey: cases[0].recoveryPublicKey,
};
const keysPayload = [["string", keys.teamId], ["string", keys.accountId], ["u32", keys.memberKeysVersion],
  ["bytes", keys.signingPublicKey], ["bytes", keys.encryptionPublicKey], ["bytes", keys.recoveryPublicKey]];
const recoveryProof = {
  keys,
  message: hex(encode([label("member-keys-recovery"), ...keysPayload])),
  signature: hex(sodium.crypto_sign_detached(encode([label("member-keys-recovery"), ...keysPayload]), signer.privateKey)),
};

writeVectors("recovery-key.v1.json", {
  file: "recovery-key.v1",
  covers: "Protocol §5.2 recovery key and recovery signing key: BIP-39 (English, 128-bit entropy, empty passphrase), keyed BLAKE2b, Ed25519; §4.2 recovery signature",
  cases,
  recoveryProof,
  refused: [
    { name: "bad checksum", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", error: "WRONG_CREDENTIAL" },
    { name: "11 words", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", error: "WRONG_CREDENTIAL" },
    { name: "word not in the list", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abacus", error: "WRONG_CREDENTIAL" },
  ],
});
