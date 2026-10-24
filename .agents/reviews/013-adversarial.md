# Review 013: adversarial, third round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `d889a7c` (after plans 013–015: D-53, held keys pinned, D-54, and reviews 011 and 012). Read only: nothing here is planned yet.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: no open finding rated medium or above; stop rule 1 of 2, waiting on this review.
- **Fresh-context reviewer.** A `general-purpose` subagent with only the adversarial brief and `docs/`, `src/`, `test/`. It returned ten candidates and reproduced six with throwaway tests kept outside the repository (A, B, C, D, F below, and the forged-anchor variant of C).
- **This session's pass,** on what D-54 added: the vault's own anchor, the roots that must agree, the owner's anchor that repairs. It found C (stale-anchor variant), reproduced with `test/security/zz-review013-repair-anchor.test.ts`, deleted after the review.
- **Double-check of the reviewer's candidates:** this session reran its six tests and read them, to check that each one asserts the claim and doesn't pass vacuously, and traced A and B in the code (`owner.ts`, `membership.ts`, `account-key-wrap.ts`, `vault.ts`).
- **Combined attackers.** A2 alone against approvals (A); A7 or A9 in the vault, with the session, against recovery and credentials (B, D); A2 with a removed member (A4), or with a relayed anchor, against the repair (C); A2 as the channel between contexts (E); any signed-in account against a kit-modelled server (F).
- **Forgeability table:** rows added for the approval handle, the recovery public key, the owner's repair anchor and the transfer request; `member-keys` now says the server can publish for any account.
- **Not checked:** the `cc1` suite internals (strict Ed25519, POPRF and DLEQ code, small-order lists), the canonical and JSON parsers' edge cases, `stream.ts` and drafts line by line, vectors, fuzzing, timing, concurrency between devices beyond what is noted.

## Findings

### A. An approval pins only `memberKeysVersion`: the server swaps the approved keys between the review and the rotation

- **Kind:** forgeable input, overclaim. **Severity:** high. The server alone gets the next team key of any team with a pending re-key, or an owner seat when the pending re-key is an owner's own. Pending re-keys are routine after `secureAccount` or a phrase replacement. Only the swapped account's session goes `unverified` (`key_mismatch`), after the key has been sealed; other members see an ordinary "re-keyed" report.
- **Where:** `src/team/owner.ts:154-163` (`#allKeys`, the team-wide list the snapshot and the proof check read); `src/team/owner.ts:176-180` (`#reviewedKeys` re-fetches the per-account list and checks only the version); `src/team/owner.ts:248` (the rotation seals to that record); `src/team/membership.ts:85` (the proof is checked on the snapshot's record). Spec: §6.5 step 3 and §6.8 step 2 ("names the `memberKeysVersion` reviewed"); SP-23 ("an approval holds for exactly the keys the owner reviewed"). This is review 009 A's gap on the other side of the approval: 009 A pinned the held keys; the approved keys are still the server's word at rotation time.
- **Evidence (reproduced, fresh reviewer):** bob re-keys with his phrase. The server serves bob's real v2 in the team-wide list and attacker keys as v2 in the per-account list. Alice's `reconcile` reports `approvedRekeys: ["bob"]`, and the attacker's encryption key opens bob's entry in version 3. With a consistent server afterwards, alice and carol stay `ready` and see `rekeyed: ["bob"]`. For alice's own re-key (D-47), version 3's owner list holds the attacker's signing key under `alice`; bob accepts it (`rekeyed: ["alice"]`), then accepts a server-signed version 4 that removes him. The same swap works on a manual `approve(handle)`.
- **Fix proposed:** the approval names the keys, not only their version. `KeysHandle` carries the `keysHash` of the record the owner reviewed (the one whose proof was checked), and the rotation seals to a record with that hash, else `STALE_VERSION` before anything is written. `reconcile` passes the snapshot's records directly. Cost: a field in a public type, §6.5, §6.8 and SP-23 wording, one test per path (proven, own, manual).
- **Needs:** a decision (it changes the public handle).

### B. Whoever holds the account key and the session splices the recovery public key: `secureAccount` fails, and the warning it gives leads the user to prove the attacker's keys

- **Kind:** forgeable input, combined attack. **Severity:** high. A documented procedure leaves a compromised user compromised. A9 in the vault usually has both, since the vault's own store port carries the session; A7 with the device's session too.
- **Where:** `src/records/account-key-wrap.ts:51-54, 78` (`wrappedRecoveryPublicKey` is a separate `wrap` under the account key, bound to `accountId, accountKeyVersion` only, §4.1); `src/account/recovery.ts:27-30` (the recovery public key is read from that field); `src/account/vault.ts:359, 365` (`secureAccount` checks the phrase against it); `src/account/recovery.ts:124-131` (`rekey-needed`). TH-12 says "Mitigated: SP-11 + SP-12 + SP-23".
- **Evidence (reproduced, fresh reviewer):** with bob's account key, the attacker keeps `wrappedAccountKey` and replaces `wrappedRecoveryPublicKey` with its own key, by a `replace` through the session. Bob's phrase still unlocks. `secureAccount({ phrase })` with the real phrase fails with `WRONG_CREDENTIAL`; `warnings()` reports `rekey-needed`; following it, `rekey(teamId, { phrase })` publishes keys carrying the attacker's recovery key, proven by bob's real phrase, and owners' `reconcile` approves them. The attacker then publishes version-3 keys proven by its own recovery key; `reconcile` approves those too, and the thief opens the current team key. Every later `createTeam` and `joinTeam` carries the attacker's key.
- **Fix proposed:** wherever the user types the phrase, trust the phrase, not the stored field: `secureAccount`, `rotate` and `rekey` check the phrase by opening the recovery wrap's `wrappedAccountKey` with the derived recovery key, use the public key derived from the phrase, and rewrite the field from it; a stored key that differs from the phrase's is reported (a new vault warning, action `secureAccount`). Operations without the phrase (`createTeam`, `joinTeam`, `warnings`) keep reading the field, which the next `secureAccount` corrects. Cost: §4.1, §5.6, §5.7, §5.11 wording, a warning code, tests.
- **Needs:** a decision.

### C. The owner's repair anchor is unauthenticated and replaces every root

- **Kind:** combined attack, missing threat. **Severity:** medium (needs the anchor to reach the user through someone other than an owner: the server relaying it, or a removed member posing as an owner).
- **Where:** `src/account/recovery.ts:74` (`const roots = ownerAnchor ? [ownerAnchor] : [newest.floor, vault]`); `src/account/recovery.ts:80` and `member-custody.ts:168-170` (`recordVaultAnchor(…, replace)`); §5.9, §6.8 step 1 ("that anchor alone"); against §5.8 step 3 ("never moving it down"). "Out of band" appears only in the guides (`using.md:124`, `integration.md:108`); no threat covers the anchor's delivery, unlike the invite anchor (TH-04).
- **Evidence (reproduced, both passes):**
  - *Stale anchor (this session):* team at version 2 with bob and carol; alice rotates carol out (version 3); bob's floor and vault anchor are at 3. The server cuts the chain at 2: `openTeam` and a plain `rekey` both refuse (`rollback`). Given version 2's real anchor, `rekey(teamId, { anchor })` succeeds: floor and vault anchor drop to 2. A new device of bob, with the server withholding `team-state`, opens the team `ready` at version 2 and writes with the team key carol still holds.
  - *Forged anchor (fresh reviewer):* an anchor naming a server-forged version 1 owned by `mallory` moves bob's floor and vault anchor there; a new device of bob opens the forged team `ready`, owners `["mallory"]`.
- **Fix proposed:** two parts. (1) Name the threat, as TH-04 names the invite: the repair anchor must reach the user from an owner outside the server, accepted as an integration duty, in SP-07's Limit and §6.8. (2) Harden against the stale variant: a repair keeps every root the served chain doesn't contradict. A root at a version the chain holds with another hash is dropped (that is the planted case), and a root above the served tip fails with `rollback`, so an older real anchor can't lower a verified state. Cost: a planted floor above the real tip can't be repaired until the chain reaches its version, so the repair then needs the vault's anchor reset, which is a second path to specify; tests for both variants.
- **Needs:** a decision.

### D. SP-25 holds against the API only: with the session, an open vault replaces the account's credentials

- **Kind:** overclaim, combined attack. **Severity:** medium (an account takeover, but the user is locked out, so it is reported, and a support restore undoes it, SP-26).
- **Where:** `src/account/vault.ts:201-206` (`if (old && …)` is the only credential check before a recovery setup); §5.6 ("a first recovery setup takes none"); `src/testing/memory-record-store.ts:220-224` (an account may delete its own wraps, as §11 allows); TH-45 ("Mitigated: SP-25"), whose actor is "holding an open vault but no credential". SP-25's Limit justifies the free first setup by "the account can't be in a team before", which a deleted recovery wrap makes false.
- **Evidence (reproduced, fresh reviewer):** through the session, the attacker deletes the recovery wrap, then runs `beginRecoverySetup` and `confirmRecoveryPhrase` with no credential, then `rotate({ phrase })` with its own phrase: bob's PIN gives `PIN_NOT_SET_UP`, his phrase `WRONG_CREDENTIAL`, and every team is re-keyed (unproven). With the raw account key, plain `replace` writes do the same without the API.
- **Fix proposed:** correct the claim: TH-45's actor holds only the open vault; with the session too (which A9 in the vault normally has), the takeover is accepted and detected, and undone by a support restore (SP-26, TH-48), like TH-11. Optional hardening: refuse a credential-free recovery setup while the account has any `member-keys-wrap` (it closes the API route, not the raw one). Cost: TH-45, SP-25 Limit, one test.
- **Needs:** a decision for the hardening; the corrected claim is an edit.

### E. A substituted transfer request hands the member's private keys to whoever substitutes it

- **Kind:** missing threat. **Severity:** medium (an integration error: a request relayed through the server, or an active A3 on the channel).
- **Where:** `src/account/member-custody.ts:209-232` and `src/records/transfer.ts:37-41` (the vault seals to any valid request); TH-39 names A9 and A3 and says "reading or replaying it gives nothing"; TH-49 covers forged transfers only. The integration guide's channel duty (`integration.md:121`) covers it implicitly.
- **Evidence (read):** code path above; nothing binds a request to the context that made it. The keys sealed are the signing seed, the encryption key, the `teamStateKey` and the floor: the team, and the owner signing key when the member is an owner.
- **Fix proposed:** TH-39 adds A2 (when it carries the channel) and the substituted request, with the impact and the same disposition as TH-49 (integration duty, D-29).
- **Needs:** an edit.

### F. The testing kit lets any signed-in account delete public write-once records

- **Kind:** spec → code, spec gap. **Severity:** medium (a server modelled on the kit lets one member rewrite items without the server's help, which removes TH-50's barrier, and lets any account stop a team).
- **Where:** `src/testing/memory-record-store.ts:151-153, 220-224` (`ownOnly` checks only private types, so `delete` works on any public record); scope rule 3 ("never overwrite write-once records") and §11 don't say public records are never deleted; scope says the kit "applies every server rule of protocol §11".
- **Evidence (reproduced, fresh reviewer):** an unrelated account deletes carol's `member-keys` (every member gets `key_mismatch`) and the newest `team-key-version`; a member deletes and re-creates `item-1` with other content, and the owner opens it.
- **Fix proposed:** §11 and scope rule 3: public key records (`member-keys`, `team-key-version`, `item`, `inbox`) are never deleted through `RecordStore`, only archived by the server's own rules; the kit refuses such deletes (`Forbidden`), with a test.
- **Needs:** an edit.

### G. `secureAccount`'s same-PIN refusal can be skipped with a split budget

- **Kind:** hardening. **Severity:** low.
- **Where:** `src/account/vault.ts:385-394` (`#refuseCurrentPin` returns on `PIN_RATE_LIMITED`); §5.1 lets the server split the budget by purpose. Related to 012-C (the skip isn't specified).
- **Evidence (read):** with the `unlock` share spent and the `enroll` share open, the check is skipped and the old PIN can become the new one; the retired version then still opens with it (SP-19).
- **Fix proposed:** with 012-C's edit, say the check is skipped when the budget is spent, and that a skipped check is reported in the result, so the integration can ask for another PIN.
- **Needs:** an edit.

## Dropped

- **Archived recovery wraps revived by the server** steer new keys to an old recovery key: the server breaking rule 7 with the old phrase is TH-48 and the TH-36 residual.
- **Local storage deleted or replayed by A7 or A9** reads as absent: SP-07's assumption (local storage keeps its state), the TH-46 residual for `team-state`, and the retired-version residual (TH-12, SP-19).
- **SP-09 overstates:** its Assumptions already say an archived old wrap opens with the old credential.

## Edits ready now (no decision)

E, F, G, and D's corrected claim.

## Not found

- The vault's export, open and leave check verify from every root, and a re-key with conflicting roots writes nothing (D-54).
- `team-state` and the local anchor can't choose the chain: a forged one gives `state_conflict` or `rollback`, never a root, when a floor exists.
- Proven re-keys are checked against the held keys pinned by the roster (009 A holds).
