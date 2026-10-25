# Plan 020: a malformed `team-state` is absent with a floor; the re-key writes `team-state` (reviews 024 A, 025 B; accept 025 C; text for 024 B, C, 025 D, E)

## Context

Review 024 (`change`, plan 019) and review 025 (`adversarial`, fresh context) found nothing critical or high. Two findings are for the action rule to fix, and one is accepted:

- **024-A / 025-A** (medium, A11 alone): a `team-state` that fails its shape checks (`parseTeamState`) stops the team with a floor too, before D-62's "absent" branch. `leaveTeam` and `exportTeamKeys` fail too, and a record with `v: 2` or an unknown suite reads as `UNSUPPORTED_VERSION`.
- **025-B** (medium, one actor in practice: A9 in the vault, or A7 with a signed-in device): a readable forged `team-state`, written with a copied `teamStateKey`, survives `secureAccount`, because the old bundle stays held until approval. Every open is then `state_conflict`, so a sole owner's own `reconcile` never approves the new keys, and the copied owner key stays valid until support restores.
- **025-C** (medium, availability, A11 on an owner's account): a garbage team key version at the next version stops the chain for good. Accepted and documented: both fixes are costly (a server signature check, or a support exception to rule 3).

The rest is text: 024-B, 024-C, 025-D and 025-E.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-62 amended (024-A) | Free | Removes a failure mode. With a floor, a `team-state` whose `revision` reads but whose other fields fail is absent like an unreadable one. With no floor it still fails | None. Users: a malformed `team-state` no longer stops a team whose keys hold a floor |
| D-63 (025-B) | Small | One best-effort write after the re-key's batch: `team-state` with the re-key's verified tip, under the new keys' `teamStateKey`. No new state, fallback, duty or error | None. Users: `secureAccount` followed by the owner's own `reconcile` closes the window again |
| 025-C | Small (text) | Accepted: TH-25, an SP-18 Limit, the integration guide, a ledger residual | Integrators: a recommendation (grant the owner capability only to cryptographic owners); no new duty |
| 024-B | Small (text) | Scope rule 4 and §11: a `team-state` write is accepted only at current revision + 1, or 1 for the first | Integrators: the Go key store checks it, if it doesn't already |

Reach: unchanged. API: no change.

## Design

### D-62 amended: a malformed `team-state` is absent with a floor

Read `revision` first: an integer from 1 to 2^53 − 2. If the revision itself fails its checks, the record is `MALFORMED_RECORD`, as today. It can't be replaced by compare-and-set, and a server that numbers by one (024-B) never stores such a record.

Then any other failure counts as "doesn't open": the shape, the version, the suite, the context, or the decryption. With a floor the record is absent, and the anchor advance replaces it at revision + 1, under the same roster rule as D-62. With no floor it fails with the error it fails with today: `MALFORMED_RECORD`, `UNSUPPORTED_VERSION` or `TRUST_FAILURE` (`state_unreadable`). `team-state` is the account's own private record, so treating an unknown version as absent loses nothing: rule 1 of §10 (readers ship first) concerns records other writers produce, and the only writers of this one are this account's own clients.

Rejected:
- Narrowing the claim to well-formed records and accepting the rest (TH-46 residual). The text needed to explain the difference costs more than the branch.

### D-63: a re-key writes `team-state` under the new keys

After the re-key's batch commits (§6.8 step 1, `rekeyTeam`), the vault writes `team-state`:
- **What:** the tip of the chain it just verified from its roots (the floor of the new keys).
- **Key:** the new bundle's `teamStateKey`.
- **How:** compare-and-set on the revision it reads. If the record is absent, the expected revision is null; if it is malformed, the revision is read as in D-62.
- **On conflict:** retry once.
- **On any failure:** the re-key is not failed. The state stays as it was, as before this decision.

The forged record goes to the archive (rule 7). This covers every re-key: `secureAccount`, `rekey`, and the repair with an owner's anchor.

Revisits D-52's reason for keeping a readable forged `team-state`, which was to keep evidence of a split view. The overwrite happens only at a re-key, which is a user's response to compromise or a repair, and the archive keeps the evidence.

Rejected:
- **Writing it inside the re-key's batch.** A concurrent anchor advance would then fail the whole re-key with `STALE_VERSION`.
- **A support step in the remedy instead.** It would leave a documented procedure that leaves the user compromised until a human acts.

### 025-C accepted

TH-25 gets an Attack and a Disposition sentence:
- **Attack:** an owner's session, or anyone the integration grants the owner capability, publishes a version that fails its checks at the next version.
- **Disposition:** a chain can't leave a version out, and the version's identity is write-once, so the team stops for good for every member. The server's check of the caller (rule 8) is the barrier.

The rest:
- **SP-18:** a Limit, "a team key version that fails its checks stops the chain (TH-25)", tested.
- **Integration guide:** grant the owner capability only to the chain's owners; a server that can verify a version's signature against the previous version's owners should.
- **Ledger:** a residual (A11 or an owner-capability holder; availability; the revisit condition is a server-side signature check, or support freeing a version identity).

### Text

- **024-B:** scope rule 4 and §11's `team-state` row: "accepted only at the current revision + 1 (1 for the first)".
- **024-C:**
  - Fix the `openTeamState` comment in `src/records/team-state.ts`.
  - Update the course (`learning/course/03-the-team/03-anchors.md`, `02-the-account/answers.md`) through maintain-course.
- **025-D:** TH-20 and §5.11 step 2: "a planted floor, or a planted bundle with none, on a device whose vault never verified the team, is trusted …"; the TH-20 residual row names both.
- **025-E:** §6.1 step 7: "check that the chain contains one at or below its tip; a newer one is left to the next open".

## Ripple

- **Spec:** §4.4, §6.1 steps 1 and 7, §6.8 step 1, §11, scope rule 4.
- **Decisions:** D-62 (amended), D-52 (status: revisited by D-63), D-47 and TH-12 (the remedy now holds).
- **Threats and properties:** TH-20, TH-25, TH-46, SP-07, SP-18, SP-26.
- **Guides and course:** the integration guide, the using guide if it names the remedy, the course.
- **Retired terms:** "fails to decrypt" where it now means "doesn't open". Check before adding.

## Phases (one commit each)

1. **Spec.** The D-62 amendment, D-63, 025-C's acceptance and the text items; run `check:spec`.
   - Before it, a `design` review of D-62 amended and D-63, with a fresh-context reviewer. Questions:
     - Who controls the revision read from a malformed record?
     - Can a re-key's write move an anchor back for a context with no local anchor?
     - Can two contexts take turns?
2. **Code and tests.**
   - **Code:**
     - `records/team-state.ts`: a revision reader separate from the full parse.
     - `team/anchors.ts`: `readServerState` treats any other failure as `anchor: null`.
     - `team/load.ts`: no floor means the original error is rethrown.
     - `account/recovery.ts`: `rekeyTeam` writes the state after its commit.
   - **Tests:**
     - `record-archive.test.ts`: a malformed state, with a short ciphertext and with `v: 2`, is replaced with a floor.
     - `rollback.test.ts`: a malformed state with no floor still fails.
     - `secure-account.test.ts`: a readable forged state, `secureAccount`, then the sole owner's own `reconcile` approves and the team opens. Also: a concurrent advance doesn't fail the re-key.
     - `key-substitution.test.ts` or `chain.test.ts`: SP-18's Limit, where an owner's session publishes a garbage version and every member is `unverified` (`bad_signature`).
   - **Guards:**
     - The full parse moved back in front of the keys.
     - The re-key's write removed.
     - The write made fatal (the concurrent-advance test fails).
3. **Notes.** Execution notes, then a `change` review of plan 020 and a fresh `adversarial` review toward the stop rule.

## Execution notes

(empty)
