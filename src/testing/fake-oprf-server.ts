// RFC 9497 POPRF server for tests (§5.1, SP-08, D-53): one key pair per key id, one total budget per account.
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { string } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import { RateLimitedError } from "../errors.js";
import type { OprfEvaluation, OprfService, OprfSettings } from "../ports.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";

export interface FakeOprfOptions {
  /** Evaluations allowed per account, across both purposes (default 10). */
  readonly budget?: number;
}

export class FakeOprfServer implements OprfService {
  readonly #keys = new Map<number, { secretKey: Uint8Array; publicKey: Uint8Array }>();
  readonly #attempts = new Map<string, number>();
  readonly #budget: number;
  #newestKeyId = 1;

  constructor(options: FakeOprfOptions = {}) {
    this.#budget = options.budget ?? 10;
  }

  async evaluate(request: Parameters<OprfService["evaluate"]>[0]): Promise<OprfEvaluation> {
    const used = this.#attempts.get(request.accountId) ?? 0;
    if (used >= this.#budget) throw new RateLimitedError();
    this.#attempts.set(request.accountId, used + 1);
    if (!Number.isInteger(request.oprfKeyId) || request.oprfKeyId < 1 || request.oprfKeyId > this.#newestKeyId) throw new Error("unknown OPRF key");
    const { secretKey } = await this.#key(request.oprfKeyId);
    // `info` from the account charged, never from the request (scope rule 2); the proof nonce from libsodium.
    const info = labelled("pin-oprf", string(request.accountId));
    const rng = (length?: number) => CURRENT_SUITE.randomBytes(length ?? 32) as Uint8Array<ArrayBuffer>;
    const { evaluated, proof } = ristretto255_oprf.poprf(info).blindEvaluate(secretKey, request.blindedElement, rng);
    return { evaluatedElement: evaluated, proof };
  }

  /**
   * What the integration ships in its client code (`settings.oprf`): every key's public key, and the
   * newest as `writeKeyId` unless another is given (D-53).
   */
  async clientSettings(writeKeyId = this.#newestKeyId): Promise<OprfSettings> {
    const keys: Record<number, Uint8Array> = {};
    for (let id = 1; id <= this.#newestKeyId; id++) keys[id] = (await this.#key(id)).publicKey;
    return { keys, writeKeyId };
  }

  /** A new key pair; the previous ones keep evaluating, as during a transition period. */
  rotateKey(): number {
    this.#newestKeyId += 1;
    return this.#newestKeyId;
  }

  /** Every evaluation counts, whatever its purpose (§5.1). */
  attempts(accountId: string): number {
    return this.#attempts.get(accountId) ?? 0;
  }

  resetBudget(accountId: string): void {
    this.#attempts.delete(accountId);
  }

  // Keys are drawn on first use: libsodium may not be loaded when the server is constructed.
  async #key(oprfKeyId: number) {
    let key = this.#keys.get(oprfKeyId);
    if (!key) {
      await ready();
      key = ristretto255_oprf.poprf(new Uint8Array(0)).deriveKeyPair(CURRENT_SUITE.randomBytes(32), labelled("pin-oprf"));
      this.#keys.set(oprfKeyId, key);
    }
    return key;
  }
}
