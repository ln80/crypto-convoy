# Review 014: design of plan 016 (D-55, D-56)

Mode: `design`, with a fresh-context reviewer. Input: plan 016's first design (D-55 rules 1–3, D-56 rules 1–4), at `d889a7c`. Read only.

## Checked

- **Fresh-context reviewer:** a `general-purpose` subagent with the design brief, the proposal, `docs/` and the account and owner code; not `.agents/`. It confirmed both problems in today's code and listed every place an approval's record is fetched (`#reviewedKeys` only), the stored recovery key is read (`recoveryPublicKey`, `currentRecoveryKey`, `recover`'s comparison) and a recovery signature is made (`createMemberKeys`, reached from `confirmRecoveryPhrase`, `secureAccount`, `rekey`).
- **This session:** the same inventory (`grep` over `src/`); the rules cover every signing path. Each finding below was checked against the code it cites.
- **Not checked:** reproduction (the findings are read from the code; the plan's tests reproduce A and B).

## Findings

### A. Two records for one version break D-55

- **Kind:** forgeable input. **Severity:** high (D-55 would leave 013-A open for the owner's own re-key).
- **Where:** `owner.ts:154-170` (`#allKeys`, `#publishedKeys` keep duplicates); `owner.ts:212-217` and `membership.ts:148` (`selfHeld` is a set of versions); `membership.ts:101` (the handle is the list's last record, in the server's order).
- **Evidence (read):** the server lists bob's genuine v2 and a forged v2: the custody check matches the genuine one, the handle takes the forged one's hash, and the rotation seals to it.
- **Fix (taken):** two records for one (account, `memberKeysVersion`) in any list the owner reads are `TRUST_FAILURE` (`key_mismatch`); the server's write-once rule makes them equivocation.

### B. Refusing a spliced wrap in `recover` locks the user out of the repair

- **Kind:** hardening (of the proposal). **Severity:** medium.
- **Where:** `vault.ts:277`; proposal rule 3.
- **Evidence (read):** the phrase has already opened `wrappedAccountKey`; a user with no PIN (D-40) can't unlock elsewhere, so can't run `secureAccount`, which rewrites the wrap.
- **Fix (taken):** rules 1–3 merge into one: given a phrase, the vault checks it by opening `wrappedAccountKey` and uses the key derived from it for everything it writes or signs; a stored key that differs is reported (`recovery-key-mismatch`, action `secureAccount`), never refused. `recover` stops refusing.

### C. The accepted residual understates what a server adds

- **Kind:** wrong claim (of the proposal). **Severity:** medium.
- **Where:** `membership.ts:85` (proofs checked against the held keys' recovery key); D-43's server rule is defence in depth.
- **Evidence (read):** in a team whose held keys carry the splicer's recovery key, the splicer's re-keys stay proven; ending the sessions stops a session holder, not a server colluding with it, which can publish proven keys above the user's after `secureAccount`.
- **Fix (taken):** the residual names A2 with the splicer, until an owner approves the user's re-key by hand (TH-12 Limit).

### D. Same version, another hash is equivocation, not staleness

- **Kind:** hardening. **Severity:** low.
- **Where:** `owner.ts:93` (`reconcile` retries on `STALE_VERSION`).
- **Fix (taken):** at rotation, a newer version is `STALE_VERSION`; the handle's version with another hash is `TRUST_FAILURE` (`key_mismatch`), which marks the session `unverified`.

### E. `secureAccount` reads the new phrase's key back from the server

- **Kind:** hardening. **Severity:** low.
- **Where:** `vault.ts:373`.
- **Fix (taken):** covered by the merged rule: the key comes from the typed phrase.

### F. Smaller points

- D-55 rule 3 ("nothing else changes") states no rule: moved to the consequence.
- The carried-key check of `oldPhrase` reads served records the bundle doesn't bind (`member-keys-wrap.ts:146-147`): a usability guard (a phrase no team key carries is refused before signing), not a security rule; owners check the roster-pinned keys. Kept, described as such.
- A first recovery setup is decided by whether the server serves a recovery wrap (`vault.ts:201-206`): this is review 013 D, open, outside this plan.
- A server replaying the pre-replacement recovery wrap at the same version makes the current phrase fail (SP-09 Limit, D-45): unchanged.

## Simpler alternative considered

A locally pinned recovery key (like the vault's anchor) would remove `oldPhrase` and the residual on that device, at the cost of one more local value and its own forgery rules (any script in the origin). Not taken: the residual is bounded by `secureAccount` and an owner's approval.
