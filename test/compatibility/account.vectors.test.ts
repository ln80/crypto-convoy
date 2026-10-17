/**
 * Replay of pin-key.v1.json and recovery-key.v1.json (§5.1, §5.2).
 * SP-08: the PIN key needs the server's per-account evaluation.
 */
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { derivePinKey } from "../../src/account/pin-key.js";
import { deriveRecoveryKey, deriveRecoveryKeys } from "../../src/account/recovery-key.js";
import { hasValidRecoveryProof, type MemberKeys } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

interface PinKey {
  rfc9497: { seed: string; keyInfo: string; skSm: string; vectors: { input: string; blind: string; blindedElement: string; evaluationElement: string; output: string }[] };
  composition: {
    inputs: { accountId: string; pin: string; salt: string; opslimit: number; memlimit: number; oprfKeyId: number; serverSeed: string };
    intermediate: { argon2id: string; oprfInfo: string; serverSecretKey: string; blind: string; blindedElement: string; evaluatedElement: string; oprfOutput: string };
    outputs: { pinKey: string };
  };
}
interface Recovery {
  cases: { phrase: string; accountId: string; seed: string; recoveryKey: string; recoveryPublicKey: string }[];
  recoveryProof: { keys: Record<string, string | number>; signature: string };
  refused: { name: string; phrase: string; error: string }[];
}

const pin = loadVectors<PinKey>("pin-key.v1.json");
const recovery = loadVectors<Recovery>("recovery-key.v1.json");

describe("pin-key.v1", () => {
  it.each(pin.rfc9497.vectors)("RFC 9497 finalize for input $input", (v) => {
    expect(tohex(cc1.oprfFinalize(unhex(v.input), unhex(v.blind), unhex(v.evaluationElement)))).toBe(v.output);
  });

  it("composes Argon2id, the OPRF and keyed BLAKE2b into the PIN key", async () => {
    const { inputs, intermediate, outputs } = pin.composition;
    const kdf = { salt: unhex(inputs.salt), opslimit: inputs.opslimit, memlimit: inputs.memlimit, oprfKeyId: inputs.oprfKeyId };
    expect(tohex(cc1.passwordHash(new TextEncoder().encode(inputs.pin), kdf.salt, kdf.opslimit, kdf.memlimit))).toBe(intermediate.argon2id);
    // A server holding the vector's per-account key; the client's random blind cancels out.
    const oprf = {
      currentKeyId: async () => 1,
      evaluate: async ({ blindedElement }: { blindedElement: Uint8Array }) =>
        ristretto255_oprf.oprf.blindEvaluate(unhex(intermediate.serverSecretKey), blindedElement),
    };
    const pinKey = await derivePinKey(cc1, oprf, { accountId: inputs.accountId, pin: inputs.pin, kdf, purpose: "unlock", min: kdf });
    expect(tohex(pinKey)).toBe(outputs.pinKey);
    expect(tohex(cc1.oprfFinalize(unhex(intermediate.argon2id), unhex(intermediate.blind), unhex(intermediate.evaluatedElement)))).toBe(intermediate.oprfOutput);
  });
});

describe("recovery-key.v1", () => {
  it.each(recovery.cases)("derives the seed, recovery key and recovery signing key of $phrase", ({ phrase, accountId, seed, recoveryKey, recoveryPublicKey }) => {
    expect(tohex(cc1.recoverySeed(phrase))).toBe(seed);
    expect(tohex(deriveRecoveryKey(cc1, accountId, phrase))).toBe(recoveryKey);
    const keys = deriveRecoveryKeys(cc1, accountId, phrase);
    expect(tohex(keys.recoveryKey)).toBe(recoveryKey);
    expect(tohex(keys.signing.publicKey)).toBe(recoveryPublicKey);
  });

  it("checks a recovery signature over member keys (§4.2)", () => {
    const { keys, signature } = recovery.recoveryProof;
    const record = {
      suite: cc1,
      teamId: keys["teamId"],
      accountId: keys["accountId"],
      memberKeysVersion: keys["memberKeysVersion"],
      signingPublicKey: unhex(keys["signingPublicKey"] as string),
      encryptionPublicKey: unhex(keys["encryptionPublicKey"] as string),
      recoveryPublicKey: unhex(keys["recoveryPublicKey"] as string),
      recoverySignature: unhex(signature),
    } as unknown as MemberKeys;
    const recoveryKey = unhex(recovery.cases[0]!.recoveryPublicKey);
    expect(hasValidRecoveryProof(record, recoveryKey)).toBe(true);
    expect(hasValidRecoveryProof(record, unhex(recovery.cases[1]!.recoveryPublicKey))).toBe(false);
    expect(hasValidRecoveryProof({ ...record, memberKeysVersion: 3 }, recoveryKey)).toBe(false);
  });

  it.each(recovery.refused)("refuses $name", ({ phrase, error }) => {
    expect(() => deriveRecoveryKey(cc1, "alice", phrase)).toThrow(expect.objectContaining({ code: error }));
  });
});
