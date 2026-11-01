# External audit brief

Where an external audit of crypto-convoy should spend its time: the areas the project's own checks covered least. Kept by the [protocol-review](../skills/protocol-review/SKILL.md) workflow. A review that leaves an area unchecked, or a model that leaves a case out, adds it here; an area an audit or a deeper review covers leaves, with where it was covered.

**Status:** no audit engaged (2026-11-01). The stop rule's other prerequisites are met: freeze candidate since reviews 040 and 041, formal models done (plan 027, review 042). The audit is the last step before the first release freezes the vectors (§13). Until then, the cheaper steps at the end lower the risk, not replace the audit.

## What the project has already checked

So an auditor can weigh it, not repeat it:

- **Spec consistency:** `npm run check:spec` (labels, ids, § references, vectors, traceability, errors, retired wording).
- **Tests:** unit, property and compatibility projects; one adversarial test file or more per security property, required by the traceability test; frozen vectors from independent generators (`test/vectors/`); a bounded, opt-in fuzz project over record parsers (`test/fuzz/`).
- **Formal models:** Tamarin models of the transfer (§3.8), the team key chain and roster seals (§4.5, §6.x) and the recovery proof (§4.2, §6.8), with the accepted attacks found as traces and each check guarded by a mutation (`formal/README.md`).
- **Reviews:** 42 reviews in five modes (`.agents/reviews/`), with every finding and accepted risk in the [ledger](ledger.md) and the [forgeability table](forgeability.md). All were run by AI agents; the `adversarial` ones by a reviewer with a fresh context. **No human cryptographer has reviewed the design or the code.** That alone is reason enough for the audit.

## Focus areas

Ranked by what a flaw would cost and how little it was checked. Each names the reviews that left it out.

### 1. The `cc1` suite and libsodium use (highest)

`src/suites/cc1/` (`sodium.ts`, `small-order.ts`) and `src/blocks/`: strict Ed25519 verification, the low-order point lists, the POPRF and its DLEQ proof (§5.1), sealed boxes with context (§3.2), `wrap` (§3.1), randomness, key wiping. Every review that touched it read only through its interface; none read it line by line (reviews 013, 016, 019, 022, 025 and 037 list it under "not checked"). The vectors pin outputs, not edge cases: no Wycheproof-style suite runs against it.

### 2. Parsers, canonical encoding and the validation order

`src/encoding/` (canonical, JSON, base64url, link values) and `src/records/`: the canonical encoding of §1, the bounds of §2, and the validation order of §8 (shape, then version and suite, then crypto, failing closed). Reviews spot-checked them; the fuzz project is bounded and opt-in. A parser accepting two encodings of one value, or reading past a bound, breaks rule 3 or rule 4 of `AGENTS.md`.

### 3. The content layer (§7)

`src/content/` and `src/blocks/stream.ts`: chunked streams, drafts, items and parts, inboxes and submissions, link shares and `link-client.ts`. Unchanged since review 015; `stream.ts` and the drafts were never read line by line (reviews 006, 009, 011, 013, 015, 019, 022, 037); no formal model covers it (out of plan 027's scope). Truncation, chunk reordering, a final-chunk flag, a part moved between items, and partial plaintext on failure (rule 5) are the questions.

### 4. Roots and rollback (D-50, D-52, D-54, D-66)

`src/team/anchors.ts`, `load.ts`, `chain.ts` and the vault's floor writes (`src/account/`). The most amended area of the protocol: D-54 and D-58 are the decisions the ledger cites most, and reviews 035, 037 and 041 each found something here (037-D, 037-E and 041-A are accepted). The formal chain model does not cover it (review 042 C): it keeps one anchor per member, with no floor, local anchor or vault anchor. Questions: can any actor alone write a root, move a floor down or sideways, or make a new device or a receiving context start from a chain the account never verified?

### 5. Recovery, `secureAccount` and re-keys (§5.6–§5.11, §6.8, D-49, D-56, D-58–D-60)

`src/account/recovery.ts`, `rotation.ts`, `member-custody.ts` and `src/team/membership.ts`. Amended often (D-56, D-58, D-60), and the flows are long: rotate, re-key every team, report failures, retry with an old phrase. The recovery model covers the proof but not freshness (review 042 D): that `reconcile` never approves earlier proven keys again rests on `proofOf`'s version check alone. Partial failures (one team's re-key failing mid-way) and what each leaves for an attacker are the questions.

### 6. Races between devices

Concurrent rotations, `reconcile` racing a re-key, two devices re-keying, `STALE_VERSION` and its single retry (§6.6, §6.9, D-64). Listed as not checked by reviews 013, 016, 022, 025, 037, 038 and 040; the tests use one in-memory store and serialised calls.

### 7. The browser adapter in real browsers

`src/browser/`: IndexedDB key store, `take-link-key.ts` (link keys from the URL fragment). Tested in Node with a fake IndexedDB only. Questions: non-extractable storage, what survives a cleared site, the fragment's exposure (history, referrer, extensions).

### 8. Side channels and memory

Constant-time comparisons, key wiping in JavaScript (copies the runtime keeps), error messages and timing that tell one failure from another (rule 6). Out of scope of every review.

### 9. Integration duties

What the protocol leaves to the integration (`docs/scope.md`, the integration guide): an authentic channel between contexts (D-29, TH-49), invite links delivered outside the server (TH-04), the vault isolated from team sessions, ending other sessions before `secureAccount` (D-43). Questions: is each duty stated so an integrator can't miss it, and is any accepted risk acceptable only if the integrator does more than the guide says? doconvoy's `e2eev2` module is a sample integration to check against.

### 10. Limits of the formal models

From `formal/README.md` and review 042: several owners per version (TH-38 without a stolen key), owner signing key replacement, owners as readers, team key secrecy beyond three versions, the `member-keys` check of a transfer, and owners' own re-keys (D-47). An auditor with Tamarin experience could extend the chain model; the models also rest on Tamarin's soundness and on the symbolic, ideal-primitive view.

### 11. Accepted residuals

The [ledger's residuals table](ledger.md#residuals): whether each acceptance holds, and whether two chain. The most consequential: TH-17 (one stolen owner key takes a team over, detection only), TH-20 (an injected script in the vault), TH-04 (first contact), TH-38 (split views, no key transparency).

## Out of scope for the audit

The product built on the library (doconvoy), the server's implementation (its contract is in scope, §9 above), PIN guessing beyond the OPRF's rate limit (AS-05), availability.

## Before an audit: cheaper steps

None replaces an audit; each narrows what it must find.

- **Wycheproof vectors** for Ed25519, X25519 and the sealed box against `cc1` (area 1).
- **A longer fuzz run** of `test/fuzz/`, and fuzzing of the canonical decoder and link values on their own (area 2).
- **A second implementation** of the vectors: doconvoy's Go key store already reads some records; checking every vector there catches encoding ambiguity (area 2).
- **Line-by-line `change` reviews** of `stream.ts` and `cc1`, which the reviews so far skipped (areas 1, 3).
- **A race test harness** that interleaves two clients' calls on one store (area 6).
- **Funded audits for open-source security software** exist (for example OSTIF, the Open Technology Fund's Red Team Lab, NLnet's NGI funds); check their current terms if the library is published as open source.

When an audit is scheduled, give the auditor this file, `docs/`, `src/`, `test/`, `formal/` and the ledger, and ask for findings rated with the [severity rubric](../skills/protocol-review/SKILL.md#severity-rubric).
