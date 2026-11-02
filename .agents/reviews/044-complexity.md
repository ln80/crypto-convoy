# Review 044: complexity, after plans 026 and 027

Mode: `complexity`. Scope: §3.7, §3.8, §4.3, §4.4, §5–§7 of `docs/protocol.md`, the floor decisions (D-48, D-50, D-51, D-52, D-54, D-66; D-62, D-63 superseded), the integration guide's Duties table, `src/team/load.ts` and `anchors.ts`, at `56fcfde`, against review 039 (`7bf7ab2`). Read only.

## Checked

- **Baseline.** `check:spec` passes. Ledger: 2 of 2, no open finding. Since review 039: plan 026 (D-66, `team-state` retired), plan 027 (formal models, no protocol change), reviews 040 to 043, and a code clean-up (`56fcfde`: dead code, module-local exports, unused-code checks on).
- **Inventory** of review 039's measures, at this commit.
- **Retirement and deletion tests** on what D-66 left: the roots (§6.1 step 1), the floor's writers (§4.3, §5.7–§5.9, §5.11), the vault's own anchor (D-54), the retired §4.4 and the pre-D-66 layouts named in §3.8 and the code.
- **Merge test** on the floor rule, which `protocol.md` names 24 times, and on the Duties table against the sections it summarises.
- **Decision log:** decisions amended more than once.
- **Not checked:** the content layer (§7), unchanged since review 015, and the browser adapter: both in the [audit brief](audit-brief.md) (areas 3, 7). The vault's memory state was not recounted: no plan since review 039 added any.

## Counts

| Measure | Review 039 (`7bf7ab2`) | Now (`56fcfde`) | Change |
| --- | --- | --- | --- |
| Roots of trust for a team | 6 | 5 | −1: `team-state` (D-66). Left: the floor, the local anchor, the vault's anchor, an invite anchor, an owner's repair anchor |
| Local values (§3.7) | 4 | 4 | — |
| Vault warnings | 6 | 6 | — |
| Error codes | 14 | 14 | — |
| `TRUST_FAILURE` reasons | 8 | 6 | −2: `state_conflict`, `state_unreadable` (D-66) |
| Server write ops | 5 | 4 | −1: `compare-and-set` (D-66) |
| Words in §5–§7 | 6,703 | 6,515 | −3%: D-66 |
| Decisions | 65 | 66 | +1: D-66, a deletion; D-62, D-63 superseded |
| Accepted residuals | 42 | 42 | — in number: D-66 retired the `team-state` rows, reviews 041 and 043 added theirs |

Method: words counted from `## 5.` to `## 8.`, the same way at both commits (review 039's table said 6,707). The Duties table has 16 rows at both commits; review 039 counted 25 duties by clause, which is not repeated here.

**Reading.** Every measure stayed level or went down. §6.1 lost its "with a floor / with no floor" branches, and `loadChain` is one line of roots (`src/team/load.ts:30`). No rule was added since review 039.

## Retirement and deletion tests

- **The vault's own anchor (D-54).** Kept. It is the one root a server can't roll back with an older wrap (the floor travels in the wrap), and review 039 kept it for the same reason; after D-66 nothing else does that job.
- **The local anchor in the vault's context.** Kept. A session in the vault's context advances it on every load; the vault's anchor moves only at the vault's own opens and exports. Without it, a refresh after the vault's open would start from an older root.
- **§4.4 and key-hierarchy's retired section.** Kept as stubs: ids are stable (spec guide).
- **The pre-D-66 layouts named in §3.8 step 3 and `member-keys-wrap.ts:128`.** Kept: they say what a reader refuses, and the tests for it need the sentence.
- **Nothing else** exists only for a combined-actor attack that D-66 didn't already retire.

## Decision log

The fold proposed for the floor is already in place: D-54 states "the current floor rules, in one place", and D-48, D-50 and D-52 point to it; D-58 has its current rule (review 039 B). One status line still carries retired detail (C).

## Findings

### A. §5.11 step 2 says a planted bundle with no floor is trusted

- **Kind:** stale text (D-66), and a merge. **Severity:** low (wrong text, no security consequence: the code refuses such a bundle). **Disposition:** correct the text.
- **Where:** `protocol.md` §5.11 step 2: "on one whose vault never did, a planted floor, or a planted newest bundle with none, is trusted (TH-20)". Since D-66 a bundle without a floor doesn't open and is absent (§4.3, D-58); TH-20 and SP-07 already say so. The rest of the sentence restates §5.9's re-key rule.
- **Evidence:** read: `src/records/member-keys-wrap.ts:128` refuses every length but 104 bytes; SP-07's Verification names the test.
- **Fix:** "Each new floor comes from a chain containing every root the vault holds (§5.9), so a floor planted with the stolen account key fails the team instead of being carried, on a device whose vault verified the team; on one whose vault never did, a planted floor is trusted (TH-20)." Add "planted newest bundle with none" to `scripts/retired-terms.json`.

### B. The Duties table still says invite anchors go outside the server, with no exception

- **Kind:** stale text (review 043 A), merge. **Severity:** low. **Disposition:** correct the text.
- **Where:** `integration.md` Duties, row "Deliver invite anchors, and owners' repair anchors, outside your server…". Review 043 A added the anchor code for an integration whose server sends the link, in the Invites section; the table, "what an integration must do … in one list", doesn't name it, so an integration that reads only the table either thinks it can't send invites or misses the code.
- **Fix:** "Deliver invite anchors, and owners' repair anchors, outside your server, or compare the invite's anchor code before approving; re-join an existing member only with an owner's anchor | TH-04, D-54, D-59".

### C. Citations of the floor rule point to amended decisions

- **Kind:** simplification (decision log). **Severity:** none. **Disposition:** correct the text.
- **Where:**
  - D-52's status ends "With a floor, a `team-state` under keys being replaced is absent (D-63)": D-63 is superseded and the record retired; the sentence before already says so.
  - `using.md:86` credits the floor's advance to D-52; its current rule is D-54 (§5.8).
- **Fix:** drop D-52's last status sentence; cite "§5.8, D-54" in `using.md`.

## Edits ready now (no decision)

A, B, C.

## Stop rule

No finding the action rule fixes: A and B correct text, C tidies citations. The count stays **2 of 2**.
