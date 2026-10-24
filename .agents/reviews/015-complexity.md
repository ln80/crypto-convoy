# Review 015: complexity, after plan 016 and the hardening direction

Mode: `complexity`, the first under the [hardening direction](../guides/direction.md). Scope: §5–§7 of `docs/protocol.md`, the decisions, `docs/integration.md`, and the account and owner code, at `7978c94`, against review 011 (`831f0fb`). Read only.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: every finding of review 013 fixed or accepted; open, all low: 011-A, 012-A, B, D, E, F. Since review 011: plan 016 (D-55, D-56), review 013's edit-only fixes (scope rule 3, the `enroll` share), the acceptances of 013-C and 013-D, and the hardening direction itself.
- **Inventory** of the trust-source branches (review 011's table), plus the counts the direction adds: remembered state, roots of trust, public API, integration duties and user-visible failures, measured at three commits.
- **Retirement test** on every rule that exists only for a combined attack; **deletion** and **merge** tests on what plan 016 added; the **decision log** for decisions amended more than once.
- **Not checked:** the stream and draft machinery, the IndexedDB adapter beyond its labels, the testing kit beyond scope rule 3. Residuals are `residuals` mode's.

## Counts

Review 011 counted only the branches that choose a trust source or a value; the other rows have no earlier baseline and start here.

| Measure | Before plan 013 (`3acbee7^`) | Review 011 (`831f0fb`) | Now (`7978c94`) | Grown by |
| --- | --- | --- | --- | --- |
| Branches choosing a trust source or value | — | 3 | 4 | D-56: the recovery key new keys carry is the typed phrase's, or the stored one without a phrase |
| Roots of trust for a team | 4 | 6 | 6 | D-54 (the vault's anchor, the owner's repair anchor) |
| Local values (§3.7) | 3 | 4 | 4 | D-54 |
| Vault memory state (besides the account key) | 1 | 2 | 3 | plan 014 (`pin-upgrade-failed`), D-56 (`recovery-key-mismatch`) |
| Vault operations (§12) | 19 | 19 | 19 | — |
| Options on those operations | — | — | +1 | D-56 (`rekey`'s `oldPhrase`) |
| Public types changed | — | — | 1 | D-55 (`KeysHandle.keysHash`) |
| Vault warnings | 4 | 5 | 6 | plan 014 (`pin-upgrade-failed`), D-56 |
| Owner warnings, `needsHuman` reasons | 4, 5 | 4, 5 | 4, 5 | — |
| Error codes | 14 | 14 | 14 | — |
| Integration guide bullets | 28 | 30 | 30 | plans 013–015; plan 016 lengthened two |
| Words in §5–§7 | 5,695 | 5,887 | 6,080 | +3% then +3% |
| Decisions | 53 | 54 | 56 | D-54, D-55, D-56 |
| Accepted residuals | 24 | 26 | 30 | 016, 013-C, 013-D, 013-E |

**Reading.** Since review 011 the growth is one branch, one memory flag, one warning, one option, one field and four documented residuals; no new root, local value, port or error. That is the shape the direction asks for: the two high findings were fixed with free or small changes, and the medium ones were accepted as text. The growth that matters for products came earlier (plans 013–015: two roots, a local value, three port methods, a warning) and is examined in the retirement test below.

## Retirement test

Rules that exist only for an attack needing two actors, and what deleting them would lose:

- **The vault's own anchor (D-54).** It closes review 009 B: an account-key holder plants a floor and a server serves a matching forged chain, and `secureAccount`, the documented remedy for a misused device, carries the forged floor. Deleting it saves a local value, three `DeviceKeyStore` methods and one root, but returns that case, and integrators rely on `secureAccount` as the remedy (TH-10, TH-20). The roots-disagree failure and the owner's repair would stay anyway: a planted floor fails every open even with an honest server. **Kept;** it belongs to the server-controlled history group, and key transparency would retire it.
- **The same-PIN refusal (D-54, 013-G).** It narrows the retired-version residual (SP-19), which needs a server and an old account key. Small: one evaluation, one refusal, no state. **Kept** as a small change the direction allows; it would go with the retired-version residual if account versions ever get transparency.
- **`recovery-key-mismatch` (D-56).** Needs the account key and the session, which a script in the vault holds alone: one actor in practice. **Kept.**
- **The `team-state` anchor checked against the chain (`state_conflict`, D-52).** One comparison, detection only. **Kept.**

Nothing else in §5–§7 exists only for a combined attack. The rules plan 016 added close one-actor attacks (D-55: the server alone; D-56: a vault script alone).

## Deletion test

- **D-55:** one field and two checks, each with a test that fails without it (plan 016's guards). Kept.
- **D-56:** replaced one helper by three (`typedPhrase`, `phrasePublicKey`, `oldPhraseSigner`), but removed a mixed branch and a refusal; `oldPhrase`'s carried-key check is a typing guard (review 014 F), one comparison. Kept.
- **011-A** (a missing floor makes `team-state` a root) is unchanged and still open, with the same advice: only alongside another layout change.

## Merge test

- D-56's rule is stated in §4.1, §5.6, §5.11, §6.8, SP-23 and TH-12, each slice citing D-56; D-55's in §6.5, §6.6, §6.8, §6.9 and SP-12. Per-operation slices, as review 011 accepted for the floor. No merge.
- The owner's repair anchor being trusted as given is now said in TH-04, SP-07, §6.8 and both guides. The protocol and guide sentences are operational; TH-04 explains the impact. No merge.

### A. The integrator's duties have no single list

- **Kind:** simplification. **Severity:** low (no security consequence; a product cost that stays invisible).
- **Actors:** none. **Disposition:** correct the text.
- **Where:** `docs/integration.md` (30 bullets across 12 sections, mixing duties, such as "carry the request on a channel the server can't write", with advice, such as batching approvals); `docs/scope.md` lists the server contract but not the client-side duties.
- **Evidence (read):** the duties added by D-29, D-43, D-53, D-54, D-55, D-56 and the acceptances of 013-C, 013-D and 013-E are spread across sections; this review could count bullets, not duties, so the [product cost](../guides/direction.md#product-cost) of each plan isn't measurable from the guide.
- **Fix proposed:** a short "Duties" table at the top of the integration guide: one row per thing the integration must do, citing the decision or threat that requires it; advice stays in the sections. Complexity reviews count its rows. Budget class: free (text only). Product cost: none; it makes onboarding shorter.
- **Needs:** an edit.

## Decision log

D-48's current rule was folded into D-54 by review 011 C; D-49 is amended once (D-56), D-39 once (D-52). Nothing amended twice since. No fold needed.

## Not a finding

- The growth since review 011 (see Counts): each item comes from a one-actor fix in the free or small class.
- Three helpers for phrases instead of one: each has one job, and the branch they replaced mixed two rules.

## Edits ready now (no decision)

- A: the Duties table in `docs/integration.md`.
- Still open from earlier reviews, all low text: 012-A, B, D, E, F; they should be done before the freeze.

## Stop rule

Nothing this review found is for the action rule to fix: A is a text correction. With review 013's findings all fixed or accepted, this is **1 of 2**; a fresh `adversarial` review that finds nothing to fix makes the freeze candidate.

## Applied

- A: the integration guide opens with a Duties table (15 rows, the baseline for later counts); its `delete` row now follows scope rule 3.
- Review 012's A, B, D, E and F, corrected with this review.
