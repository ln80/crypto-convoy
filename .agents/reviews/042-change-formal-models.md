# Review 042: change, the formal models (plan 027)

Mode: `change`, on the models only. Scope: `formal/transfer.spthy`, `formal/chain.spthy`, `formal/recovery.spthy`, `formal/README.md` and the SP Verification lines that cite them, against §3.8, §4.1, §4.2, §4.5, §5.6, §5.11, §6.1, §6.4–§6.9, at `29cd0d6`. The question: does any model abstract away a case of the protocol so that a lemma holds in the model and not in the protocol, and does any text claim more than the lemmas prove? Read only; two throwaway model variants were run in the scratchpad and deleted.

## Checked

- **Baseline.** `check:spec` passes; `check:formal` passes (about 13 minutes, every lemma as expected, every mutation caught). The ledger stood at 2 of 2 with no open finding.
- **Each rule against its § step.** Transfer: the box's contents and context (§3.8 step 2), the receiver's checks and single use (step 3); the `member-keys` check is left out and listed. Chain: version 1 (§6.3), rotation (§6.6), reader checks 1–3 and the roster entry (§4.5), the join with and without the anchor (§6.4). Recovery: the phrase's key (§5.2), keys with and without the phrase (§6.8 step 1, D-56), the stored key's rewrite (§4.1), the proof check against the held keys (§4.2, SP-23).
- **Direction of each abstraction.** An abstraction is safe when the model's honest parties accept at least what the protocol's accept, and its attacker can do at least what the protocol's can. Safe in that sense: the receiver's key revealed even after it is wiped; `reconcile` approving any account, owners included, and any version (§6.9 approves fewer); one record per version identity for honest owners, with forgeries free under a stolen key; any record served in any order. Not safe, or not stated: A, D, E.
- **Each lemma against the sentence that cites it.** SP-02, SP-04, SP-05, SP-06 and SP-23 match what their lemmas prove. Two lemmas prove less than their comment says (B); SP-07's line reads as covering more than its lemma (C).
- **Not checked:** the Tamarin proofs themselves (the tool's soundness), the Dockerfile's pinned binaries beyond their hashes, and `check-formal.mjs`'s parsing beyond the runs above.

## Findings

### A. The model binds roster seals tighter than §4.5, and previous-key links looser

- **Kind:** model abstraction. **Severity:** low. **Actors:** none (model only). **Disposition:** loosen the model's seal to the team alone (model edit), so every abstraction of the chain is on the safe side.
- **Where:** `chain.spthy` seals `<'roster-seal', T, vid, tk>`, where `vid` names the version and, through its parent, the whole chain below it. §4.5 seals with `u32 n, bytes keysHash`: the version number and the member's keys, not the record or the chain. So in the protocol a seal can be copied between two records of the same version on two branches; in the model it can't. The link `senc(ptk, tk)` binds nothing, where §4.5 binds `teamId, n`: looser, so safe.
- **Evidence:** reproduced. A copy of `chain.spthy` sealing `<'roster-seal', T, tk>`, looser than §4.5 (no version, no keys), gives every lemma as expected in both runs: the structural lemmas verified, the three attacks found (TH-38 in 679 steps), and with DEPTH3 `team_key_reaches_only_rostered_accounts` verified in 41 steps. So no result rested on the tighter binding; it only needs to stop being tighter than the protocol.
- **Fix:** seal with the team alone in every rule, and say in the README that the model's seal is looser than §4.5 and its link carries no context.

### B. Two lemmas compare version identities, not the key held

- **Kind:** model lemma weaker than its comment. **Severity:** low. **Disposition:** strengthen the lemmas (model edit).
- **Where:** `anchored_join_holds_the_real_version` concludes `Version(t, v, …)`, and `no_fork_without_owner_key` concludes `v2 = v3`: both about the version's identity, which a forgery may reuse. SP-07 and SP-05 mean the real record, so the real key. The model's rules do give the real key (the join requires the invite's record, and an advance requires the held owner's signature), but the lemmas wouldn't catch a change that broke that while keeping the identity.
- **Evidence:** reproduced. Stronger forms, `Holds(m, t, v, o, tk)` at the anchored join implies `Version(t, v, tk, o, b)`, and two accepts from one owner give `v2 = v3 & tk2 = tk3` unless its key was stolen, verify in 10 and 18 steps.
- **Fix:** replace both lemmas with the stronger forms (same names), and the README rows.

### C. SP-07's formal line reads as covering rollback and roots, which no model does

- **Kind:** overclaim (of verification). **Severity:** low. **Disposition:** correct the text; accept the gap until the external audit.
- **Where:** SP-07's Verification cites `anchored_join_holds_the_real_version` and `attack_TH04_first_contact`: the join from an invite anchor only. SP-07's property is mostly about anchors and roots: refusing a chain without the anchor, the floor as a root, both in every context (D-50, D-54, D-66). Plan 027's model 2 row listed "a chain without every root is refused" and 041-A; the execution notes record them as not modelled, but SP-07's line and the README don't say so.
- **Evidence:** read: `chain.spthy` keeps one anchor per member, the version it holds, and has no floor, local anchor or vault anchor; the README says so under abstractions, not under SP-07.
- **Fix:** SP-07's line: "covers the join from an invite anchor; rollback and roots are not modelled". The README gets a "Not covered" list per model (with C, D, E).

### D. "The version number proves nothing": it orders re-keys, which the model leaves out

- **Kind:** model abstraction, wrong claim. **Severity:** low. **Disposition:** correct the text.
- **Where:** `recovery.spthy`'s header and the README say the version number and self-signature "prove nothing about who made the keys". True of who, but the version is what keeps an earlier proven record from being approved again: `proofOf` requires the new keys' version above the held keys' (`src/team/membership.ts:93`), and §6.9's `rekey-awaiting-approval` means newer keys. The model's `reconcile` approves any proven record, an earlier one included, and `proof_needs_the_phrase` holds for it, since the user did make it. So the model approves more than the protocol (safe for its lemmas), but no lemma states freshness: re-approving earlier keys whose private half was copied (A7) is outside the model.
- **Evidence:** read (code path above).
- **Fix:** "the version number orders re-keys: `reconcile` approves only keys newer than those held (§6.9), which the model doesn't state; the self-signature proves nothing about who made the keys."

### E. Abstractions the README doesn't list

- **Kind:** model abstraction, stale text. **Severity:** low. **Disposition:** correct the text.
- **Where and why:**
  - **Chain, readers:** `Advance` and the joins take the member from the record's second roster slot, so an owner never follows the chain as a reader. The checks don't depend on the role, but the lemmas are proven only for that slot.
  - **Chain, owner keys:** one signing key per account, never replaced, so reader check 3's "same `accountId` **and** same key" and the owner key replacement of §6.7 and §6.8 step 3 (an old owner key refused after a re-key) are not modelled.
  - **Transfer, request:** the request carries the team in the model; in §3.8 it is the receiver's public key alone, and which team to export is the integration's (D-29). The same under an authentic channel, and the attacker chooses it on one it writes.
- **Fix:** list each in the README's abstractions for its model.

## Edits ready now (no decision)

A and B (model and README, then `check:formal`), C, D, E (text).

## Stop rule

This review checks the models, not a protocol change: nothing in it is for the action rule to fix in the protocol, and no finding changes the threat model. The count stays **2 of 2**. With B to E done, the models' claims match what they prove; next, the external audit, with C's gap (rollback and roots, D-54, D-66) and D's (freshness of proven re-keys) named in its brief.
