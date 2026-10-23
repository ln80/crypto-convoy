# Review 006: adversarial, first round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `3dc80a4` (after plan 011). Read only: nothing here is planned yet.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: no open finding. Since review 005: plan 011 (D-51).
- **Fresh-context reviewer.** A `general-purpose` subagent given only the adversarial brief and `docs/`, `src/`, `test/` (no plans, reviews, ledger or conversation). It returned five candidates, ranked: B and C below (it called them high), A (which this session found too), D and E. It wrote no tests (read only); every candidate was reproduced here.
- **Forgeability.** The [table](forgeability.md) checked against the code: the `team-state`, local anchor and `item` rows corrected (below); the reviewer's inventory agrees with the other rows.
- **Combined attackers.** A2 + A4 and A2 + A5 against items (A); A2 + A9 and A2 + A7 against anchors (B); A2 with the TH-20 attacker against `team-state` (C); A2 + A10 against link shares (D); A2 then A1 against the PIN (E). A2 + A11, A2 + A6, A7 + A11, A8 + A11 and A2 + an integration error gave nothing beyond TH-11, TH-17, TH-36 to TH-38, TH-41, TH-45 to TH-47 and TH-49.
- **Double-check:** A to E reproduced with a throwaway test (`test/security/zz-review-006.test.ts`, five cases, deleted after the review).
- **Not checked:** parsers and canonical encoding edge cases (the fuzz project covers them), the chunk logic of `blocks/stream.ts`, `reconcile` edge cases beyond SP-23, the testing kit, timing and side channels, A3 (TLS assumed, AS-04), and actors × operations one by one for the owner operations.

## Findings

### A. A holder of an older team key version and the server rewrite or add items

- **Kind:** combined attack (missing threat). **Severity:** medium (two actors; forged content for every member, silently).
- **Where:** `src/team/session.ts:232-246` (`#itemKey` opens `record.teamKeyVersion`, any version at or below the member's own); §7.2; §11 (write-once and "current version" are server rules only); TH-06 and TH-15 (the latter says "the server still can't change the author recorded on an item"); SP-03.
- **Evidence (reproduced):** bob is removed (version 3). He builds a record for an existing item `plan`, at version 2, with `createdBy: "alice"` and new parts; the server serves it. Carol opens `plan` and reads bob's text. Same for a new item id. A current member (A5) can do the same with the server. SP-03 holds against the server alone, not against a key holder with it.
- **Fix proposed:** an accepted threat, unless the protocol takes on author signatures (D-09) and something that fixes when a record was written. Name it (TH-50: a key holder with the server rewrites or adds items; accepted, the barrier is the server's write-once rule), add a Limit to SP-03 and correct TH-15's last sentence. Cheap hardening: expose the item's `teamKeyVersion` on the opened item, so an integration can flag items at a version older than a member's removal. Cost: one field in the API.
- **Needs:** a decision (accept, or the hardening).

### B. A forged local anchor above the floor drops the floor; the forged team then spreads through `team-state`

- **Kind:** forgeable input, combined attack. **Severity:** high (a documented remedy leaves the account compromised; one team's context reaches another team).
- **Where:** `src/team/load.ts:28-29` (the floor is dropped when it is below every other anchor); `src/team/chain.ts` (the first fetched record is checked by the anchor hash only); `src/team/anchors.ts:52-58` (`advanceAnchor` writes the tip under the real `teamStateKey`); `src/browser/indexeddb-local-key-store.ts:120-121` (any script in the origin can set any team's anchor with the non-extractable key); §6.1 step 1, D-50 read rule, D-51 Consequence ("A local anchor a script or a thief changed stops only that device"), SP-07.
- **Evidence (reproduced):** a script in the origin with no key of the team (A9, in another team's page in a same-origin layout), or A7, writes bob's local anchor for the team: version 9, the hash of a version the server forged (owned by mallory, rostering bob's real keys). The server removes or withholds `team-state` and serves the forged version 9. Bob's device opens `ready` at version 9: the floor (version 2) is below the local anchor, so it isn't counted, and version 9 is trusted by its hash alone. `advanceAnchor` writes version 9 into `team-state` under bob's real key. A new device of bob's, with no tampering of its own, opens the forged team; `secureAccount` then puts version 9 into every bundle's floor (D-51 takes the `team-state` anchor). Review 005's test missed it because bob didn't open the team between the tampering and `secureAccount`.
- **Root, with C:** every anchor is a root of trust on its own. A record at an anchor's version is accepted by its hash, with no link to anything older, and the floor, the one root the vault built, is dropped as soon as a higher anchor exists. Whoever can write a local anchor or a readable `team-state` chooses the root.
- **Fix proposed (with C):** the floor is the root, and every other anchor must link to it.
  1. **Read:** §6.1 always counts the floor; the chain is fetched from the floor and must contain every anchor. A forged anchor no longer links. Cost: every open fetches the records since the floor instead of since the lowest anchor, which D-48 and D-50 rejected; bounded by how often the floor moves (2).
  2. **Write:** at a re-key and a rotation, the floor moves to the tip of the chain verified from the current floor (§6.1 steps 1–2), not to the highest anchor read. Cost: one chain fetch per team at each re-key and rotation, `secureAccount` included (the alternative review 005 set aside).
  3. Optionally, to bound (1): advance the floor at other writes the vault already makes. Needs a design review of its own.
- **Needs:** a decision (amends D-50 and D-51).

### C. A stolen `teamStateKey` writes a forged anchor that `secureAccount` puts into the floor

- **Kind:** forgeable input, wrong claim (D-51 Consequence). **Severity:** high (the documented remedy for TH-20 leaves the account compromised).
- **Where:** `src/account/recovery.ts:86-93` (`newestTrustedAnchor` takes the highest of the floors and the `team-state` anchor, unchecked); `src/team/anchors.ts:26-28` (any bundle's key opens `team-state`, the old ones included); `src/account/member-custody.ts:232-239` (the clean-up after an approval re-writes the server anchor under the newest key); D-51 ("what reaches the floor was written … by `advanceAnchor` from a verified chain"); TH-20, TH-46.
- **Evidence (reproduced):** the TH-20 attacker (A9 in the vault, or A7, holding bob's bundle) writes a valid `team-state` with a forged anchor at version 9 under bob's `teamStateKey`. Bob runs `secureAccount`, the documented remedy: it re-keys the team, and the new bundle's floor is version 9. A new device of bob's served the forged version 9 opens it at version 9. With an honest server, the same write alone makes every new device fail the team, and restoring `team-state` doesn't help: the anchor is in the floors.
- **Fix proposed:** B's (2): the floor moves only along a chain verified from the current floor. A forged anchor doesn't link, so the re-key fails for that team (`failed` in the report) instead of spreading it; (1) keeps a forged `team-state` from opening anything.
- **Needs:** a decision, with B.

### D. A link holder and the route rewrite a shared item for other link recipients

- **Kind:** overclaim. **Severity:** low (needs a link holder and the route; members detect it; a capability holder can publish anything under the link anyway).
- **Where:** §7.3 ("the recipient … opens parts", integrity of content and manifest for link recipients); `src/content/link-client.ts:32-33`, `src/records/item.ts:135-141` (the manifest is checked under the item key only).
- **Evidence (reproduced):** with the item key from the link, re-encrypt new parts and a new manifest, keep the record's `wrappedItemKey`; a link recipient opens the forged text, a member gets `DECRYPTION_FAILED` (the item key wrap binds the manifest).
- **Fix proposed:** a Limit in §7.3 and TH-23: a link recipient can't tell content the team wrote from content written by another holder of the link with the route's help. Binding the manifest hash into the link would close it, at the cost of a longer link and a new link version; not proposed.
- **Needs:** an edit.

### E. An OPRF answered with the identity makes a PIN wrap crackable offline

- **Kind:** missing threat. **Severity:** medium (two actors: a server that controls the OPRF responses for a while, then a data thief).
- **Where:** §5.1 (base-mode OPRF, no proof); `src/suites/cc1/index.ts:227-238` (only the all-zero element is refused); `src/account/vault.ts:238-242` (a moved `currentKeyId` forces a re-enrolment at the next unlock); TH-07, TH-09.
- **Evidence (reproduced):** an `OprfService` that returns the blinded element unchanged (key 1). A PIN set up against it opens on another device with the same identity service, so no server secret is involved: the wrap depends on Argon2id of the PIN alone, and a later data thief (A1) guesses offline. A2 can force it at any time by moving `currentKeyId`, which re-enrols every account at its next PIN unlock.
- **Fix proposed:** a verifiable OPRF (RFC 9497 VOPRF mode): the server proves its evaluation against a public key the client knows. The key must reach the client outside the server (AS-02: the integration's code), and rotations need a list of accepted public keys. Cost: a proof per unlock, key distribution, a new wrap layout version (the key id names a public key). Or accept it in TH-09, as part of trusting the OPRF service.
- **Needs:** a decision.

## Edits ready now (no decision)

- D: the Limit in §7.3 and TH-23.

## Need a decision

- **B and C together (high):** the floor as the root (read: always counted; write: moved only along a verified chain). Amends D-50 and D-51; corrects D-51's Consequence and SP-07.
- **A (medium):** accept as a named threat, with or without the `teamKeyVersion` hardening.
- **E (medium):** VOPRF, or accept in TH-09.

## Unconfirmed

- The reviewer noted that a script can lower the local account key version (`indexeddb-local-key-store.ts:111`), making an existing device stateless for SP-19's Limit; useful only with a third actor holding a retired account key. Not reproduced; low.

## Forgeability table

Updated: the `team-state` row (any context that holds a `teamStateKey` produces a readable one; a source of the floor since D-51), the local anchor row (writable by any script in the origin; it drops the floor when above it, B), the `item` row (older-version holders with the server, A). Status line set to this review.

## Decided

- **B, C: done (plan 012, D-52),** after design review 007: the floor is the root of trust, advanced when the vault opens or exports the team, and verified from the device's anchor at `secureAccount`.
- **D: done (plan 012):** §7.3 and TH-23.
- **A: accepted (user).** TH-50, SP-03 Limit with its test, TH-15 corrected, the integration guide (enforce write-once and the current version in the server). The guide's `replace` row, which plan 012 missed, now names `member-keys-wrap`.
- **E: done (plan 013, D-53),** after design review 008: POPRF with proofs checked against keys pinned in client settings, and the key id writers use a setting.
