# Review 025: adversarial, seventh round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `81b60c3` (after plan 019). Read only.

## Checked

- **Baseline.** `check:spec` passes; ledger 0 of 2; review 024 (`change`, plan 019) found one small fix (024-A) and three edits.
- **Fresh-context reviewer** with the adversarial brief, D-62 named as the newest rule, no access to `.agents/` or history. It found no critical or high finding. It reproduced F1 to F3 with throwaway tests and deleted them; this session reran F2 and a variant of F3 (below) and read F4 and F5 in the code.
- **Forgeability.** The `team-state` rows updated for D-62; the `team-key-version` row names an owner's session.
- **This session's pass** on D-62: who makes a `team-state` unreadable (A11, A2, a stale context), who replaces it (only keys the tip's roster holds), and whether a replacement moves anything back (only with A2, who could already withhold it, review 023 A). Nothing beyond 024-A.
- **Pairs checked, nothing beyond accepted threats:** A2 + A11, A2 + A9 (TH-49), A2 + A4 (TH-50, TH-05), A2 + A6 (TH-38), A8 + A11 (TH-41, TH-47), A2 with a relayed link or transfer (TH-04, TH-21, TH-23, TH-49). The owner overview pins held keys to the roster hash, so the server can't choose the recovery key a proof is checked against.
- **Not checked:** the cc1 suite internals, parsers beyond reading (no fuzzing), account rotation and recovery setup in depth, inbox code beyond a skim, the browser adapter, timing and races between devices.

## Findings

### A. A malformed `team-state` stops the team with a floor: the same as 024-A, with a wider impact

- **Kind:** overclaim, spec → code. **Severity:** raised to medium. **Actors:** A11 alone. **Disposition:** fix, as 024-A proposes.
- **What this adds to 024-A:** `leaveTeam` and `exportTeamKeys` fail too (through `loadChain`), so the user can't even leave; a record with `v: 2` or an unknown suite fails `UNSUPPORTED_VERSION`, which §9 tells the integration to answer with "update the library"; and, with a copied owner bundle, it blocks the owner's own approval after `secureAccount`, as in B. 024-A's fix (a record whose revision reads but whose other fields fail is absent with a floor) closes all of these.
- **Evidence:** reproduced by both reviewers (`anchors.ts:27`: `parseTeamState` runs outside the loop that tries the keys).

### B. A readable forged `team-state` blocks the owner's own approval after `secureAccount`

- **Kind:** wrong premise (of the TH-46 residual for a `teamStateKey` holder). **Severity:** medium (one actor in practice, see below; a documented remedy leaves the stolen owner key valid, but the failure is visible). **Actors:** a holder of a copied bundle with the session: A9 in the vault holds both, so one actor in practice; A7 with a signed-in device. **Disposition:** fix (small), or accept and document; needs a decision.
- **Where:** the ledger's residual "a readable `team-state` with a forged anchor stops the account's devices (`state_conflict`, `rollback`) until support restores" counts it as availability only. TH-12, TH-20 and D-47 say `secureAccount`, then the owner's own `reconcile`, closes the window. But `rekeyTeam` (`recovery.ts`) never touches `team-state`, the old bundle stays held until the approval, so the forged state still opens, and every `openTeam` is `state_conflict`: the owner's `reconcile` never runs. For a sole owner, or a team whose other owners don't act, the copied owner key stays the owner key until support restores the `team-state`.
- **Evidence (reproduced, throwaway test deleted):** alice, sole owner of `team-1`; a stolen `teamStateKey` writes a readable `team-state` naming a forged version-1 hash; `secureAccount` reports `{ rekeyed: ["team-1"], failed: [] }` and alice's bundle is at version 2; `openTeam` is `unverified` (`state_conflict`).
- **Fix proposed:** the re-key (§6.8 step 1, `rekeyTeam`), which already holds a chain verified from the vault's roots, writes `team-state` with that tip under the new keys' `teamStateKey`, by compare-and-set in its batch; the forged one is archived (rule 7). **Budget:** small (one operation in an existing batch; no state, fallback or duty). **Product cost:** none. It overrides D-52's reason for keeping a forged state ("evidence of a split view") only where the user is securing the account, and the archive keeps the evidence.
- **Alternative:** accept, and say in TH-12, D-47 and the using guide that a team failing `state_conflict` after `secureAccount` needs a support restore of its `team-state` before the owner's own approval; another owner can approve meanwhile.

### C. A garbage team key version from an owner's session stops the team for good

- **Kind:** overclaim, missing threat. **Severity:** medium (availability only, but permanent and for every member, with no restore; TH-25 claims it mitigated). **Actors:** A11 on an owner's account alone, or anyone the integration grants the owner capability; no keys needed. **Disposition:** accept and document (availability only; no small fix).
- **Where:** scope rule 8 checks only that the caller holds the owner capability and is the signer; the server doesn't verify the signature (D-30: "defence in depth"). Version records are write-once and a new one is accepted only as current + 1 (rules 3, 6); a chain can't leave a link out (§4.5, `chain.ts`), so every reader stops at it. Rule 7 archives private records only. TH-25 lists A11 "for the records they can publish" as mitigated by SP-18, whose "left out, stops nothing else" applies to lists, not to the chain.
- **Evidence (reproduced, throwaway test deleted):** alice's session creates version 3 as a copy of version 2 with `version: 3`; the kit accepts it; bob's open is `unverified` (`bad_signature`); alice's `reconcile` throws `TRUST_FAILURE` (`bad_signature`).
- **Fix options, both costly:** the server verifies each new version's signature against the previous version's owners (a new integration duty: canonical decoding and Ed25519 in the key store); or support may remove a version no client can verify and free its identity (a support duty, and an exception to rule 3). Neither is allowed for an availability finding without the user's decision.
- **Acceptance text:** TH-25 (a session of an owner account can stop the team's chain, since a chain can't leave a version out; the server's check of the caller is the barrier), TH-28's neighbour in the threat index, SP-18's Limit, and the integration guide: grant the owner capability only to the cryptographic owners, and a server that can verify signatures should. A ledger residual.

### D. A planted newest bundle with no floor is a first contact on a device with no vault anchor

- **Kind:** overclaim. **Severity:** low (the same residual as a planted floor). **Actors:** an account-key holder with the session (A7, A9) and the server (A2). **Disposition:** correct the text.
- **Where:** `recovery.ts` `rekeyTeam` takes `newest.floor` and the vault anchor only; a planted newest bundle without a floor (D-58 allows its wrap in the batch that publishes its keys) leaves no root on a device whose vault never verified the team, so the chain is verified from version 1. §5.11 step 2 says a planted floor "fails the team instead of being carried"; TH-20's residual names a planted floor, not a missing one.
- **Evidence:** read (code above), not reproduced.
- **Fix:** TH-20 and §5.11: "a planted floor, or a planted bundle with none". An edit.

### E. The anchor advance's conflict path doesn't check a newer `team-state`

- **Kind:** spec → code. **Severity:** low (nothing is adopted). **Disposition:** correct the text.
- **Where:** `anchors.ts` (after a conflict, a re-read state above the tip returns at the loop's first check); §6.1 step 7 ("reload the server's state, check that the chain contains it, then retry").
- **Fix:** §6.1 step 7: "…check that the chain contains one at or below its tip; a newer one is left to the next open". An edit.

## Edits ready now (no decision)

D and E (text); with 024-B and 024-C.

## Needs a decision

- **024-A / 025-A:** amend D-62 so a malformed `team-state` is absent with a floor (recommended).
- **B:** the re-key writes `team-state` under the new keys (recommended), or accept with a support step in the remedy.
- **C:** accept and document (recommended), or make the server verify version signatures.

## Stop rule

024-A and B are for the action rule to fix: **0 of 2**. After a plan that fixes them, a `change` review and a fresh `adversarial` review that find nothing to fix make the freeze candidate.
