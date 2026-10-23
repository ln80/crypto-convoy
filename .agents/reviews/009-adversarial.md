# Review 009: adversarial, second round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `225392a` (after plans 012 and 013: D-52, D-53, TH-50). Read only: nothing here is planned yet.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: no open finding rated medium or above; stop rule 0 of 2.
- **Fresh-context reviewer.** A `general-purpose` subagent with only the adversarial brief and `docs/`, `src/`, `test/`. It returned five candidates (A, B, C, E, F below) and reproduced A in memory.
- **This session's pass,** on what D-52 and D-53 added: the floor's advance on open and export, `secureAccount` from the local anchor, `state_conflict`, the pinned OPRF keys, `writeKeyId`, the upgrade that may fail. It found D.
- **Combined attackers.** A2 alone and A2 + A11 against `reconcile` and `overview` (A); A7 or A9 with A2 in a split layout (B); A2 + A7 against a fresh device after `secureAccount` (C); A2's front end against the upgrade (D); A4 or A5 with A2 against `inbox` records (E).
- **Double-check:** A, B, C and D reproduced with a throwaway test (`test/security/zz-review-009.test.ts`, four cases, deleted after the review). E and F read from the code.
- **Not checked:** the stream chunk logic, the content drafts and submission records line by line, the IndexedDB adapter's edge cases, fuzzing, vectors, timing.

## Findings

### A. The server picks the record of the "held" keys, so its own keys pass as a member's proven re-key

- **Kind:** forgeable input, spec → code. **Severity:** high (the server alone reads everything a team writes from the next rotation on; owners see only an ordinary "re-keyed" change).
- **Where:** `src/team/membership.ts:77-86` (`heldKeys` takes the published record at the held version from the server's list, and `proofOf` checks the proof against its `recoveryPublicKey`); `src/team/owner.ts:154-164` (`#allKeys`, unfiltered); `src/team/owner.ts:235` (approved accounts skip the pinned-hash check in `#recipients`). §4.2 and §6.8 step 2 say the proof is checked against the keys the account holds, which the roster pins by `keysHash`.
- **Evidence (reproduced):** the server publishes bait `member-keys` for bob at his next version, signed by an attacker recovery key R′ (the server rule D-43 stops a stranger, not the server; a session thief can publish it too). A dry run reports nothing proven. The server then serves, in the list `reconcile` reads, a record for bob's held version that names R′. Alice's `reconcile` approves bob's "proven" re-key and rotates; the attacker's encryption key opens bob's entry in the new version. `overview()` would show `proof: "recovery"` to an owner approving by hand too.
- **Fix proposed:** an edit to the code, the spec already says it: the held keys are the published record whose `keysHash` equals the holder's roster entry; any other record for that version is ignored (a mismatch is `TRUST_FAILURE`, `key_mismatch`, as in `#recipients`). A test with the reproduction. No decision needed.

### B. In a split layout, `secureAccount` carries a planted floor

- **Kind:** combined attack, wrong premise (D-52's accepted residual). **Severity:** high (the documented remedy leaves the account compromised; with the server, new contexts open a forged team).
- **Where:** `src/account/recovery.ts:72-73` (`fromLocal && ports.anchors ? … : null`, then `local ?? newest.floor`); `src/account/vault.ts:56-57` (`anchors` is only for opening teams in the vault's context); D-52's Consequence and the ledger residual ("on one that hasn't, verifies from the floor it holds").
- **Evidence (reproduced):** with the stolen account key (A7, A9 in the vault), bob's newest wrap is replaced with the same keys and a floor at a forged version 50. A vault with no `anchors`, as the split layout uses, runs `secureAccount`: the new keys' floor is the planted one. Its export then advances along whatever the server serves from it (`maintainBundles`), and a receiving context with no anchor starts from it. The residual D-52 accepted assumed the remedy runs where a device opened the team; in a split layout the vault never does.
- **Fix proposed:** the vault keeps its own anchor in every layout: `anchors` (the `AnchorStore` half) becomes required, and the vault's export, which already verifies the chain, writes it there, as a session's open does (§6.1 step 7). `secureAccount` then always verifies from the vault's own anchor when it has exported or opened the team. Cost: split layouts must give the vault an anchor store (its own origin's IndexedDB), and one local write per export that saw a new version.
- **Needs:** a decision.

### C. A retired account key version served to a fresh device undoes `secureAccount`

- **Kind:** combined attack (two accepted residuals chained). **Severity:** medium (two actors).
- **Where:** `src/account/unlock-methods.ts:19-29` (`currentVersion` refuses only versions below what this device saw); SP-19's Limit and TH-05 ("matters only if someone also holds that old key"); §5.11 with `newPhrase` optional.
- **Evidence (reproduced):** a device thief copies alice's open account key at version 1. Alice runs `secureAccount` without a new phrase (version 2). The server serves version 1 to a fresh device, with its archived recovery wrap; alice recovers there with her phrase and creates a team. The new member keys are wrapped under version 1's key, which the thief opens. The residual was read as "old data stays readable"; chained with TH-05, it is "new keys go under the stolen key".
- **Fix proposed:** `secureAccount` replaces the recovery phrase whenever the account key may have leaked (a device used while unlocked, TH-12, TH-20): the old version's recovery wrap then needs the old phrase, which the user no longer uses, and the fresh device fails to recover instead of opening the retired version. Either make `newPhrase` required in `secureAccount`, or require it for the device-or-script cases in the guides. Cost: the user writes down a new phrase at each `secureAccount`.
- **Needs:** a decision.

### D. A failed upgrade evaluation is silent, and costs an evaluation at every unlock

- **Kind:** hardening (detection, availability). **Severity:** low.
- **Where:** `src/account/vault.ts` `unlockWithPin` (every `ConvoyError` from the upgrade is swallowed, D-53); `warnings()`.
- **Evidence (reproduced):** a front end answers the upgrade's key id with its own key: the unlock succeeds, `warnings()` is empty, and every unlock spends two evaluations, which halves the account's budget. A forged proof there is exactly TH-51's signal.
- **Fix proposed:** keep the unlock; report the failure through `warnings()` (a new `pin-upgrade-failed` code, with whether a proof failed), and skip further upgrade attempts in this vault session. Cost: one warning code.
- **Needs:** an edit with a small API addition.

### E. TH-50 names items only; `inbox` records can be rewritten the same way

- **Kind:** missing threat (text). **Severity:** low.
- **Where:** `src/records/inbox.ts:26-33`, `src/team/session.ts:221-224`; TH-50.
- **Evidence (read):** a key holder with the server builds an `inbox` record at an old version with its own key pair. Senders seal to the public key in the link, so existing links are safe; an integration that rebuilds a link from the stored record would hand out the attacker's key.
- **Fix proposed:** extend TH-50 to `inbox` records, and say in the integration guide that inbox links are built once, at `createInbox`, never from a stored record.
- **Needs:** an edit.

### F. `advanceAnchor` stops on a newer `team-state` without checking it

- **Kind:** hardening. **Severity:** low (availability only).
- **Where:** `src/team/anchors.ts:52`, `:66`.
- **Evidence (read):** after a compare-and-set conflict, a server state newer than the verified chain ends the retry with no check; a `teamStateKey` holder can write one. The next load refuses it (`rollback`, D-52), so nothing is followed.
- **Fix proposed:** none; record it as covered by TH-46 (availability until support restores).
- **Needs:** nothing (accepted).

## Edits ready now (no decision)

- A: the held keys pinned by the roster's `keysHash`, with a test.
- D: the `pin-upgrade-failed` warning.
- E: TH-50 and the integration guide.

## Need a decision

- B: the vault keeps its own anchor in every layout (`anchors` required).
- C: `secureAccount` always replaces the phrase, or only in the guides' device-or-script cases.

## Forgeability table

Updated: `member-keys` (the held version's record, as served to `reconcile` and `overview`: A), the anchor floor (a vault without `anchors`: B), the current account key version (C).
