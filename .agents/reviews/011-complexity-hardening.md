# Review 011: complexity of the hardening series (D-41 to D-54)

Mode: `complexity`. Scope: the hardening rules added or rewritten by plans 008–015 (D-41 through D-54) in `docs/protocol.md` §3.7, §3.8, §4.3, §4.4, §5–§7, the decisions, and the code that implements them, at `831f0fb`. Read only. The review was rerun independently with GPT-5.6 Sol; the second pass produced its inventory before reading this report, then checked every claim below.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: no open finding rated medium or above. Last review: 010 (`design`). No earlier complexity review recorded rule counts; review 004, after D-48, is the comparison below.
- **Inventory** of every hardening rule introduced by D-41–D-54, then the deletion test and the merge test on each. §7 was read and is unchanged by this series (TH-50 names inboxes; it adds no content rule).
- **Code.** `src/team/load.ts` (roots), `src/account/recovery.ts` (`rekeyTeam`), `src/account/member-custody.ts` (vault anchor, advance, export), `src/account/vault.ts` (create, join, `secureAccount`), `src/records/member-keys-wrap.ts` (optional floor).
- **Second pass.** `npm run check:spec` passed again. The rollback, account-rotation and PIN-hardening suites passed, 51 tests in all. It independently confirmed A–C, corrected A's evidence and cost, and found no new medium-or-higher issue.
- **Not checked.** A line-by-line inventory of rules outside D-41–D-54, the stream and draft machinery, and the IndexedDB adapter beyond the vault-anchor label. Residuals were not re-litigated (that is `residuals` mode). Forgeability rows were read for stale restatements, not re-derived.

## Balance

The series added rules, and the floor passed through five regimes (D-48, D-50, D-51, D-52, D-54). The live protocol is smaller than the middle of that series. D-50 first consolidated the write sources; the later revisions removed unsafe fallbacks: "copy the local anchor into the floor" (review 005 A), "a higher anchor drops the floor" (review 006 B), and "if the check fails, keep the current floor" (review 010 A). D-54's live write rule has one outcome when the check fails: write nothing. The compatibility path for a bundle with no floor remains (finding A).

What remains is one read rule and one write rule, plus checks elsewhere that each close one takeover and were not amended again. That is the right side of the balance. Two leftovers are cheap to edit (findings B, C). One branch fails the deletion test and is still not worth a layout change (finding A).

### Counts

Here a **branch** means a branch that selects a trust source or value, not every refusal or optional input. Maintenance conditions are listed separately so the count doesn't mix definitions.

Review 004, the floor write rule after D-48: **2 branches** ("carry the floor, else the local anchor, else `team-state`"), the same algorithm **written in 5 places**.

Now, at `831f0fb`:

| Piece | Rules | Branches that choose a value |
| --- | --- | --- |
| Floor, read (§6.1) | 1: the chain contains every root | 1: with no floor, `team-state` is a root (finding A) |
| Floor, write (§5.8, §5.9, §6.8) | 1: the tip of a chain that contains every root the vault holds; a rotation keeps the floor | 1: an owner-supplied anchor replaces the roots |
| Vault anchor (§3.7, D-54) | 1 local value, another input to the same "contains every root" check | 0 |
| D-41 credential | 1 check before a credential change | 0 (refuse, or proceed) |
| D-42 archive | server rule; no client branch | 0 |
| D-43 version numbering | 1: newest published + 1, and a report | 0 |
| D-44 membership report | the owner-change report, extended to the roster | 0 |
| D-45 new phrase on `secureAccount` | 1 optional input | 0 |
| D-46 roster hashes | 1 check on every entry | 0 |
| D-47 own re-key | 1 case in `reconcile` | 1 |
| D-49 old phrase proves a retry | 1 extra accepted phrase | 0 |
| D-53 verifiable PIN | proof, pinned key id, `writeKeyId` | 0 trust-source branches; unpinned ids and bad proofs fail closed |
| Same-PIN refusal (D-54) | 1 check | 0 |

Fallbacks removed since D-48 and not restored: floor counts only with no other anchor; floor filled from the local anchor; floor filled from `team-state`; failed verification keeps the current floor.

Two maintenance conditions don't select a trust source: advance a floor only when the verified tip is newer (`src/account/member-custody.ts`), and let an owner-supplied repair anchor replace even a higher vault anchor after its chain verifies.

## Deletion test

Kept, because a property sentence and a test need each:

- **D-41.** Without the credential check an open vault replaces the phrase (TH-45, SP-25).
- **D-42.** The restore path for a credential thief and for garbage private records (SP-26, TH-46).
- **D-43, D-44, D-46.** Each is one check or one report. D-46 rejected "check only the entries that changed" as a second rule. D-43 rejected "refuse gaps", which would have handed the lockout back to the thief.
- **D-45 with D-49.** One call replaces the phrase; the retry stays proven. Two operations re-keyed every team twice.
- **D-47.** The single-owner team otherwise has nobody to approve the owner's own re-key (SP-22, SP-23). Approving every owner's proven re-key was rejected: a leaked phrase would change the owner list silently.
- **The floor as a root, advanced on open and export (D-52).** SP-07. Without the advance, every open fetches from the join (review 007 A).
- **The vault's own anchor, and failing the re-key when roots disagree (D-54).** SP-07. Dropping the anchor returns review 009 B: a planted floor is the only root in a split layout. Keeping the old "else the current floor" returns review 010 A.
- **The owner anchor on `rekey` / `secureAccount`.** SP-07's repair. It is a fallback: the caller chooses the only root, the same shape as an invite (TH-04), and the using guide says an owner sends it out of band. Without it a planted floor on a device that never verified the team cannot be repaired. A script in the vault can pass one, and that script already holds the account key (TH-20).
- **Rotation keeps each bundle's floor.** Recomputing it on the way through a rotation would write a floor before the re-key has checked the roots.
- **Local anchor stays a root beside the floor.** It bounds rollback to what this device verified. The floor bounds it to what the account verified. One check takes both.
- **D-53.** Without the proof, whoever answers PIN evaluations for a while can offline-check every PIN written then (TH-51). The rejected alternatives were heavier: a key per account, which cannot be pinned, or a mode field and a second wrap version. Changing cc1 in place avoided that version branch. The integration duties (nonce, no exported tweaked key, key-id rotation) are the residual already in the ledger.
- **A new PIN that opens the current wrap is refused.** SP-11 and SP-19 disclose the retired-version risk but don't require this check. It is inexpensive defence in depth against the common same-PIN reopening path; `account-rotation.test.ts` asserts it. It costs one evaluation on the path that already has the phrase. The guides also recommend a new phrase and resetting other devices, because this check closes only one path.

### A. The missing floor still makes `team-state` a root

- **Kind:** simplification. **Severity:** low (the attacker who can strip the floor already holds the account key, which is the accepted TH-20; the branch is one conditional).
- **Where:** §6.1 step 1 ("for keys with no floor, the server's `team-state` anchor too"); `src/team/load.ts:29-32`; §4.3 reader check "97 or 137 bytes"; `src/records/member-keys-wrap.ts:42-43`.
- **Evidence (read):** every newly created bundle gets a floor. Creation sets version 1 (`member-custody.ts` `newTeamOps`), join sets the verified tip (`vault.ts:457-461`), and a re-key sets the tip (`recovery.ts:73-78`). An account rotation preserves the opened bundle exactly, so it also preserves a pre-D-48 floorless bundle (`src/account/rotation.ts`). The reader still branches:

```29:32:src/team/load.ts
  const floor = bundles[0]?.floor;
  // In the vault's context, its own anchor is a root too (D-54).
  const roots = [floor, local, ...extraRoots, floor ? undefined : server?.anchor].filter((a): a is Anchor => a !== null && a !== undefined);
  const state = floor ? server?.anchor : undefined;
```

  With no floor, `team-state` is a root and is not checked afterwards. SP-07 does not require that: it says the chain is fetched from the floor and the local anchor. No behavioral security test asserts the branch. Compatibility tests do open both layouts (`test/compatibility/blocks.vectors.test.ts`), and the frozen vectors encode a bundle without a floor. There is no released-data compatibility requirement because v1 remains unreleased, but the repository deliberately preserves the pre-D-48 format.
- **Fix proposed:** require the floor (137 bytes only). A shorter bundle is `DECRYPTION_FAILED`. Delete the conditional. Cost: change both the `member-keys-wrap` and transfer layouts and their parsers, types and vectors (`src/records/member-keys-wrap.ts`, `src/records/transfer.ts`); record a decision. Gain: one trust-source branch, and the last read-path fallback in the floor machine. An account-key holder can still plant a floor (TH-20); stripping it would then fail closed instead of selecting `team-state`.
- **Needs:** a decision. The cost spans two layouts for one conditional. Reasonable to take up only alongside another format change; until then the branch is the smaller price.

## Merge test

The live floor rule is stated once per operation (§4.3, §5.8, §5.9, §6.1, §6.4, §6.8, §3.8), each slice citing D-54. That replaces review 004's five copies of one branched algorithm. No further merge in the protocol.

The decision log and the forgeability table still restate superseded rules. Those are B and C.

### B. The forgeability table still describes the rules this series deleted

- **Kind:** stale text. **Severity:** low (the table is not the spec; the spec matches the code).
- **Where:** `.agents/reviews/forgeability.md:16` (OPRF row: `currentKeyId`, "Authenticated by: Nothing"), `:18` (a vault with no `anchors` verifies `secureAccount` from a planted floor, "review 009 B"), `:20` (`team-state` "isn't checked against a chain"; "the highest of it and the bundles' floors wins").
- **Evidence (read):** `currentKeyId` is gone from `src/` (D-53: a proof against the pinned key). D-54 fails the re-key and the export when the vault's anchor disagrees (`account-rotation.test.ts`, the split-layout case). D-52 checks `team-state` against the chain (`state_conflict`, `rollback`); D-51's "highest wins", which line 20 still states, was superseded. The session row for `team-state` (line 32) already says the floor bounds it, so the two rows disagree.
- **Fix proposed:** an edit of those three rows to the D-53 and D-54 rules. The next `adversarial` review re-derives the rest of the table; it was last checked at `225392a`, before plans 014 and 015.
- **Needs:** an edit.

### C. The current floor rule is spread across three accepted decisions

- **Kind:** stale text, simplification. **Severity:** low (a reader of the decisions can apply a superseded rule; the protocol text is the one the code follows).
- **Where:** `docs/decisions.md:583` (D-48's status names D-50 and D-52 only), D-52's status at line 648 (names the re-key amendment, not the vault anchor added to the read roots), D-54 at line 687 (states the delta). D-50's status already points at D-52 and D-54. D-51 is already Superseded.
- **Evidence (read):** the live read rule is D-52 plus the vault anchor; the live write rule is D-54; join still takes its floor from D-50. A reader who stops at D-48 or D-52 gets a rule the code no longer implements. Review 009 B was that kind of reading, applied to a fallback D-52 still stated as current.
- **Fix proposed:** an edit. Restate the current read rule and write rule in D-54, and point the status lines of D-48, D-50 and D-52 at D-54 as the current rule. The older decisions keep their history. No protocol change.
- **Needs:** an edit.

## Not a finding

- The owner-anchor repair, the vault anchor, the advance-on-open, and the same-PIN check. Each survives the deletion test; see above.
- D-41 through D-47, D-49 and D-53. One rule each, none amended twice, none with a fallback that selects an unauthenticated value.
- §7. Nothing in this series added a content branch.

## Edits ready now (no decision)

- B: three rows in `.agents/reviews/forgeability.md`.
- C: status lines and a restatement in D-54.

## Need a decision

- A, and only if a wrap-layout change is already happening. Otherwise leave the conditional.
