# Review 027: change, plan 020 (D-62 amended, D-63)

Mode: `change`. Scope: the `docs/` changes of plan 020 (`75a5ba6`, with §6.8 step 4 simplified in `36a31d5`) and what they ripple into, against the code at `9e984b7`. Read only.

## Checked

- **Baseline:**
  - `npm run check:spec` passes.
  - Ledger: 0 of 2, nothing open to fix. Still open, low: 011-A. Waiting for the next complexity review: 026-F.
  - Plan 020's full checks passed: 762 tests, browser 10, build, package.
- **Properties → protocol:** every changed sentence was traced to a § and to code:
  - SP-07: with no floor, `team-state` is a root and a failure is an error; with a floor, it counts only under the newest keys. Traced to §4.4, §6.1 step 1, and `readServerState`.
  - SP-12: a forged state under keys being replaced doesn't stop the owner's own approval. Traced to D-63 and `readServerState` (the newest bundle only).
  - SP-18: the Limit for a garbage version. Traced to §4.5 and `chain.ts`.
  - SP-26: a malformed state is replaced; an unknown version is left alone. Traced to §4.4, §6.1 step 7, and `advanceAnchor`'s `unknownVersion`.
- **Threats → mechanism:** each claim was traced to code and to plan 020's tests:
  - TH-20: a planted floor or a bundle with none; a forged state after the re-key.
  - TH-25: a version that fails its checks; reproduced in `key-substitution.test.ts`.
  - TH-46: a state that doesn't open is absent and replaced; an unknown version stays absent.
- **Decisions → text:** D-62 and D-63 searched across `docs/`, `README.md`, the guides, `src/` comments and the local course. The search covered:
  - "every bundle", "any bundle", "fails to decrypt", "rewrites the server's", `state_unreadable`;
  - the floor taken from the `team-state` anchor.

  What it found:
  - The matches left in D-51 and D-62's first Decision paragraph are history. Their status lines point to D-52 and D-63.
  - §3.8's "a value that fails to decrypt is an error" concerns local storage, not `team-state`.
- **Spec → code:**
  - The revision is read before the envelope, and a bad one is `MALFORMED_RECORD` whatever the floor.
  - An unknown `v` comes from `readEnvelope`, and an unknown suite from `suiteFor`. Both are `UNSUPPORTED_VERSION`, which sets `unknownVersion`.
  - The advance skips an absent state that is either unknown or not held. The conflict path checks only a readable state at or below the tip.
  - Clean-up always leaves the newest keys with a floor, since the same batch writes one, so §6.8 step 4 holds without a rewrite.
  - A receiving context takes its bundles, floors included, from the transfer, so the same rule applies there.
- **Plan notes:** the plan accepted one risk on its own, a session's unknown-version record that stays absent. D-62's Consequence and the ledger's TH-46 residual already record it. The doconvoy duty (revision + 1) is in the notes and in the integration guide.
- **Not checked:** doconvoy's Go key store; the opt-in fuzz run itself.

## Findings

### A. The new revision reader isn't fuzzed

- **Kind:** test coverage (hardening). **Severity:** low. **Disposition:** an edit.
- **Where:** `readTeamStateRevision` (`src/records/team-state.ts:43`) is now the first parser to see a `team-state` from the server. The fuzz parser list (`test/support/parsers.ts`) has `parseTeamState` but not this reader. SP-18 says every parser refuses malformed input with a typed error.
- **Evidence:** read. The function only checks `typeof` and integer bounds, and throws `malformed()`. No crash is known.
- **Fix:** add a `team-state revision` entry to `test/support/parsers.ts`.

## Not found

- **Old-key reads:** no path reads `team-state` with older keys where there is a floor. `readServerState` is the only reader: it is called by `loadChain` and by the advance's conflict path. The clean-up no longer reads it.
- **Contexts holding the new keys during a pending re-key:** they write no `team-state` at all; neither the advance nor the clean-up does. That is the cost D-63 accepts. The floor still bounds a new device, and the vault advances that floor on open (D-52).
- **The no-floor case:** it behaves as before plan 020. Every bundle is tried, a parse failure is thrown, and a decryption failure is `state_unreadable`. `rollback.test.ts` covers it.
- **TH-25's index row and entry:** both say "Partly mitigated" and cite SP-18; SP-18's Limit cites TH-25.

## Edits ready now (no decision)

A.

## Stop rule

Nothing here is for the action rule to fix: **1 of 2**. A fresh `adversarial` review that finds nothing to fix makes the freeze candidate.
