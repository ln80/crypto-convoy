// pin-key.v1.json: Argon2id, the RFC 9497 ristretto255-SHA512 OPRF vectors, and the final combination (§5.1).
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

// RFC 9497 Appendix A.1.1, OPRF mode, copied from the RFC.
const rfc9497 = {
  seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
  keyInfo: "74657374206b6579",
  skSm: "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
  vectors: [
    {
      input: "00",
      blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
      blindedElement: "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
      evaluationElement: "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
      output: "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
    },
    {
      input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
      blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
      blindedElement: "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
      evaluationElement: "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
      output: "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
    },
  ],
};
const { oprf } = ristretto255_oprf;
const u = (h) => new Uint8Array(Buffer.from(h, "hex"));
if (hex(oprf.deriveKeyPair(u(rfc9497.seed), u(rfc9497.keyInfo)).secretKey) !== rfc9497.skSm) throw new Error("skSm");
for (const v of rfc9497.vectors) {
  if (hex(oprf.blindEvaluate(u(rfc9497.skSm), u(v.blindedElement))) !== v.evaluationElement) throw new Error("eval");
  if (hex(oprf.finalize(u(v.input), u(v.blind), u(v.evaluationElement))) !== v.output) throw new Error("output");
}

// The protocol's composition, with the cheapest Argon2id allowed (§2 floor).
const accountId = "alice";
const pin = "1234";
const salt = fixed("pin salt", 16);
const opslimit = 2;
const memlimit = 64 * 1024 * 1024;
const oprfKeyId = 1;
const serverSeed = fixed("server oprf seed", 32);
const a = sodium.crypto_pwhash(32, Buffer.from(pin.normalize("NFKC"), "utf8"), salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
const info = encode([label("pin-oprf"), ["u32", oprfKeyId], ["string", accountId]]);
const { secretKey } = oprf.deriveKeyPair(serverSeed, info);
const { blind, blinded } = oprf.blind(a);
const evaluated = oprf.blindEvaluate(secretKey, blinded);
const y = oprf.finalize(a, blind, evaluated);
const pinKey = sodium.crypto_generichash(32, encode([label("pin-key"), ["string", accountId], ["bytes", hex(y)]]), a);

writeVectors("pin-key.v1.json", {
  file: "pin-key.v1",
  covers: "Protocol §5.1 PIN key: Argon2id, RFC 9497 OPRF (ristretto255-SHA512), keyed BLAKE2b",
  rfc9497,
  composition: {
    inputs: { accountId, pin, salt: hex(salt), opslimit, memlimit, oprfKeyId, serverSeed: hex(serverSeed) },
    intermediate: {
      argon2id: hex(a),
      oprfInfo: hex(info),
      serverSecretKey: hex(secretKey),
      blind: hex(blind),
      blindedElement: hex(blinded),
      evaluatedElement: hex(evaluated),
      oprfOutput: hex(y),
    },
    outputs: { pinKey: hex(pinKey) },
  },
  normalization: { pin: "ﬁ1", nfkc: "fi1" },
});
