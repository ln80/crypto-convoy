// pin-key.v1.json: Argon2id, the RFC 9497 ristretto255-SHA512 POPRF vectors, and the final combination (§5.1, D-53).
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

// RFC 9497 Appendix A.1.3, POPRF mode, ristretto255-SHA512, copied from the RFC (D-53).
const rfc9497 = {
  mode: "POPRF",
  seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
  keyInfo: "74657374206b6579",
  skSm: "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07",
  pkSm: "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631",
  vectors: [
    {
      input: "00",
      info: "7465737420696e666f",
      blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
      blindedElement: "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715",
      evaluationElement: "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874",
      proof: "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",
      proofRandomScalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
      output: "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221",
    },
    {
      input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
      info: "7465737420696e666f",
      blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
      blindedElement: "f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d",
      evaluationElement: "8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540",
      proof: "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908",
      proofRandomScalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
      output: "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507",
    },
  ],
};
const u = (h) => new Uint8Array(Buffer.from(h, "hex"));
const rfcPoprf = ristretto255_oprf.poprf(u(rfc9497.vectors[0].info));
const rfcKeys = rfcPoprf.deriveKeyPair(u(rfc9497.seed), u(rfc9497.keyInfo));
if (hex(rfcKeys.secretKey) !== rfc9497.skSm || hex(rfcKeys.publicKey) !== rfc9497.pkSm) throw new Error("key pair");
for (const v of rfc9497.vectors) {
  const p = ristretto255_oprf.poprf(u(v.info));
  if (hex(p.blindEvaluate(u(rfc9497.skSm), u(v.blindedElement)).evaluated) !== v.evaluationElement) throw new Error("eval");
  const { tweakedKey } = p.blind(u(v.input), u(rfc9497.pkSm));
  if (hex(p.finalize(u(v.input), u(v.blind), u(v.evaluationElement), u(v.blindedElement), u(v.proof), tweakedKey)) !== v.output) throw new Error("output");
}

// The protocol's composition, with the cheapest Argon2id allowed (§2 floor). The proof nonce is
// noble's here: a test value, never a deterministic nonce in a server.
const accountId = "alice";
const pin = "1234";
const salt = fixed("pin salt", 16);
const opslimit = 2;
const memlimit = 64 * 1024 * 1024;
const oprfKeyId = 1;
const serverSeed = fixed("server oprf seed", 32);
const keyInfo = encode([label("pin-oprf")]);
const a = sodium.crypto_pwhash(32, Buffer.from(pin.normalize("NFKC"), "utf8"), salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
const info = encode([label("pin-oprf"), ["string", accountId]]);
const poprf = ristretto255_oprf.poprf(info);
const { secretKey, publicKey } = poprf.deriveKeyPair(serverSeed, keyInfo);
const { blind, blinded, tweakedKey } = poprf.blind(a, publicKey);
const { evaluated, proof } = poprf.blindEvaluate(secretKey, blinded);
const y = poprf.finalize(a, blind, evaluated, blinded, proof, tweakedKey);
const pinKey = sodium.crypto_generichash(32, encode([label("pin-key"), ["string", accountId], ["bytes", hex(y)]]), a);

writeVectors("pin-key.v1.json", {
  file: "pin-key.v1",
  covers: "Protocol §5.1 PIN key: Argon2id, RFC 9497 POPRF (ristretto255-SHA512, D-53), keyed BLAKE2b",
  rfc9497,
  composition: {
    inputs: { accountId, pin, salt: hex(salt), opslimit, memlimit, oprfKeyId, serverSeed: hex(serverSeed), keyInfo: hex(keyInfo) },
    intermediate: {
      argon2id: hex(a),
      oprfInfo: hex(info),
      serverSecretKey: hex(secretKey),
      serverPublicKey: hex(publicKey),
      blind: hex(blind),
      blindedElement: hex(blinded),
      tweakedKey: hex(tweakedKey),
      evaluatedElement: hex(evaluated),
      proof: hex(proof),
      oprfOutput: hex(y),
    },
    outputs: { pinKey: hex(pinKey) },
  },
  normalization: { pin: "ﬁ1", nfkc: "fi1" },
});
