// RFC 9497 OPRF server for tests (§5.1, SP-08): one key per account, one total budget.
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { string, u32 } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import { RateLimitedError } from "../errors.js";
import type { OprfService } from "../ports.js";
import { CURRENT_SUITE } from "../suites/registry.js";

export interface FakeOprfOptions {
  /** Evaluations allowed per account, across both purposes (default 10). */
  readonly budget?: number;
}

export class FakeOprfServer implements OprfService {
  readonly #seeds = new Map<number, Uint8Array>();
  readonly #attempts = new Map<string, number>();
  readonly #budget: number;
  #currentKeyId = 1;

  constructor(options: FakeOprfOptions = {}) {
    this.#budget = options.budget ?? 10;
    this.#seeds.set(1, CURRENT_SUITE.randomBytes(32));
  }

  async evaluate(request: Parameters<OprfService["evaluate"]>[0]): Promise<Uint8Array> {
    const used = this.#attempts.get(request.accountId) ?? 0;
    if (used >= this.#budget) throw new RateLimitedError();
    this.#attempts.set(request.accountId, used + 1);
    const seed = this.#seeds.get(request.oprfKeyId);
    if (!seed) throw new Error("unknown OPRF key");
    // A conforming per-account key: DeriveKeyPair(seed, enc(label("pin-oprf"), u32 oprfKeyId, accountId)).
    const info = labelled("pin-oprf", u32(request.oprfKeyId), string(request.accountId));
    const { secretKey } = ristretto255_oprf.oprf.deriveKeyPair(seed, info);
    return ristretto255_oprf.oprf.blindEvaluate(secretKey, request.blindedElement);
  }

  async currentKeyId(): Promise<number> {
    return this.#currentKeyId;
  }

  /** Replaces the server seed; the previous key keeps working, as during a transition period. */
  rotateKey(): number {
    this.#currentKeyId += 1;
    this.#seeds.set(this.#currentKeyId, CURRENT_SUITE.randomBytes(32));
    return this.#currentKeyId;
  }

  /** Every evaluation counts, whatever its purpose (§5.1). */
  attempts(accountId: string): number {
    return this.#attempts.get(accountId) ?? 0;
  }

  resetBudget(accountId: string): void {
    this.#attempts.delete(accountId);
  }
}
