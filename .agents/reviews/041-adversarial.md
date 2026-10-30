# Review 041: adversarial, thirteenth round (D-66)

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/` and `src/` at `7369ded` (after plan 026 and review 040), D-66 first. Read only, except the text edits listed below, applied after it.

## Checked

- **Baseline.** `check:spec` passes; no open finding. Plan 026 changed two formats and the roots of trust after the last `adversarial` review (037), so this one targets D-66.
- **Fresh-context reviewer.** A `general-purpose` subagent with the adversarial brief, D-66 named first, and no access to `.agents/` or `learning/`. It reported four candidates, all confirmed by throwaway tests (`test/security/zz-adv-floor.test.ts`, 4 tests), which this session re-ran (all pass, so each behaviour is as described) and deleted after the review.
- **This session's checks.** A server serving an older wrap with an older floor is SP-07's accepted window; an archived bundle whose keys were replaced leaves the session `pending`. Nothing new.
- **Found sound by the reviewer:** with an honest server every root must link to the floor (`chain.ts:93-98`), so a forged local or vault anchor only fails; a lower forged local anchor can't splice in; only an account-key holder makes a wrap that opens; the floor upkeep moves only to a chain containing every root (`member-custody.ts:240-247, 287-293`); the clean-up deletes older wraps only once the tip's roster holds the newest keys.
- **Documented, not counted:** an owner leaving through a stale chain (D-65, SP-16 Limit); a rotation re-wrapping only the wraps it is served (TH-28, review 032 F); the repair through the open vault (037-D); a forged transfer (TH-49).
- **Pairs checked:** A9 + A2 (A), A2 at first contact + the repair (B), A11 + A2 (D), A2 + A4, A7 + A11, A8 + A11, A2 + A6 (TH-38) as in review 037.
- **Not checked:** §7 content, §8 order, PIN, OPRF and recovery (§5.1–§5.6, §5.10), owner operations and handles (§6.5–§6.9), parser bounds and fuzzing, the browser adapter's crypto, vectors.

## Findings

### A. A script in the vault deletes the vault's anchor, so a planted floor survives `secureAccount`

- **Kind:** wrong claim. **Severity:** medium (two actors; a guarantee the integration relies on is overclaimed).
- **Actors:** A9 in the vault (the account key, and this origin's storage) with A2 serving a forged chain.
- **Disposition:** correct the text and accept; **server-controlled history** group. It reaches what 037-D accepted (the open vault re-keys from a forged anchor) by another route; a check of the vault's anchor can't tell "deleted" from "never verified" without remembered state that the same script could delete.
- **Where:** `rekeyTeam`'s roots are `[newest.floor, vault]` with nulls dropped (`recovery.ts:155-156`); `vaultAnchorOf` returns null for a deleted anchor (`member-custody.ts:196-198`). TH-20, SP-07 Assumptions and D-54's consequence said a vault that has opened the team refuses a floor written directly.
- **Evidence:** reproduced (C1): after the plant and the two deletes, `secureAccount` reports `{ rekeyed: ["team-1"], failed: [] }`, the new floor is the forged anchor, and the team opens `ready` at version 9.
- **Text (done):** TH-20's limits, SP-07 Assumptions and D-54's consequence: the vault's anchor stops only a planter who can't also delete it; a script in the vault's origin can. Residual row added.

### B. After a forged first contact, the repair doesn't fix a receiving context

- **Kind:** wrong claim. **Severity:** low (availability: the context fails closed, `chain_conflict`).
- **Actors:** A2 at a join without an invite anchor (TH-04's accepted first contact), with a receiving context that opened the forged chain.
- **Disposition:** correct the text: an integration step in the repair, not a new duty.
- **Where:** D-54 said "a receiving context gets a new transfer"; but that context's local anchor names the forged chain and stays a root (`load.ts:24-27`).
- **Evidence:** reproduced (C2): the vault's `openTeam` is repaired, the receiver opened with a new transfer is `chain_conflict`.
- **Text (done):** D-54 and the integration guide (Key custody across contexts): after a repair, clear the team's anchor in each receiving context (`deleteAnchor`) before opening a new transfer there.

### C. A forged vault anchor fails more than re-keys and exports

- **Kind:** wrong claim. **Severity:** low (availability, that device).
- **Actors:** A9 (any script in the origin) alone.
- **Disposition:** correct the text.
- **Where:** `openSession` passes the vault's anchor as a root (`member-custody.ts:219-220`), and `currentOwners` too (`member-custody.ts:268-271`), so `leaveTeam` fails before deleting anything. D-54 said a forged one "only fails re-keys and exports".
- **Evidence:** reproduced (C3): `openTeam` in the vault's context and `leaveTeam` are `rollback`.
- **Text (done):** D-54: it fails the vault's opens, re-keys, exports and `leaveTeam` on that device, until an owner's anchor repairs it.

### D. A session replays an older wrap revision: the floor goes back for new devices

- **Kind:** missing threat (text). **Severity:** low.
- **Actors:** A11 alone writes it; it harms only with A2, which could serve an older wrap itself (SP-07).
- **Disposition:** accept and document.
- **Where:** `replace` needs only a live identity, and the wrap's associated data binds no revision (`member-keys-wrap.ts:52-57`); the vault raises the floor again at its next open (`member-custody.ts:287-293`). TH-46 named garbage and deletion only.
- **Evidence:** reproduced (C4): with an honest server a new device trusts floor 1, and with the chain rolled back to 1 opens there with no failure.
- **Text (done):** TH-46's disposition names the replay and points to SP-07's accepted window.

## Edits applied

A, B, C, D: TH-20, TH-46, SP-07 Assumptions, D-54 (decision and consequence), the integration guide. `check:spec` passes.

## Forgeability

- Vault's own anchor: deletable by any script in its origin, which turns an opened vault into one that never verified the team (A).
- `member-keys-wrap`: a session replays an older revision, which opens with an older floor (D).

## Stop rule

Nothing here is for the action rule to fix (A is a combined attack, B to D availability or text). With review 040 (`change`), two reviews in a row in different modes, this one `adversarial` with a fresh-context reviewer, found nothing to fix, and no finding is open: **2 of 2, freeze candidate**, now covering D-66. Next: the formal model (the transfer, the roster seals, the recovery proof) and the external audit, before the vectors freeze (§13).
