# Review 040: change, plan 026

Mode: `change`. Scope: plan 026's spec (`880d770`), code, tests and vectors (`03dffb5`), and what they ripple into, at `c8ab76c`. Read only, except the two edits listed below, applied after it.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 2 of 2 (037 `adversarial`, 038 `change`, 039 `complexity`); plan 026 closes 011-A, 026-F, 028-C, 039-A, 039-B.
- **Properties → protocol.**
  - SP-07: "nothing the server stores is a root" is §6.1 step 1 and `loadChain` (`load.ts:24-28`); "required in every bundle" is §4.3 and `unwrapMemberKeys`; the new Verification sentences each have a test in `rollback.test.ts` (the forged local anchor on its own device, the 97- and 137-byte bundles, the retired transfer entry).
  - SP-26: the archive list (account key wraps, member keys wraps) is scope rule 7 and the testing kit's `PRIVATE` set.
  - SP-12: its removed sentence named a deleted test; nothing else cited it.
- **Threats → mechanism.** TH-05, TH-20, TH-39, TH-46, TH-49 and their index rows no longer cite `team-state`; TH-20's "a bundle without a floor doesn't open" is the D-66 test. TH-46's index row cites D-42 and D-58, as its entry does.
- **Decisions → text.** Every document and `README.md` searched for `team-state`, `teamStateKey`, the two reasons, compare-and-set, "revision", "server anchor", "server copy" and "team states": matches only in history sections (D-42, D-48 to D-63, D-66) and the removed §4.4 and rule 4. D-25, D-54's Read bullet and the §10 citation were current text and were corrected in phase 1.
- **Spec → code.** §6.1 step 7 is `advanceAnchor` (never down); §3.8's entry is `sealTransfer` / `openTransfer`; §11 and §12 match `ports.ts` (no `TeamStateKey`, no `compare-and-set`); §9 matches `errors.ts`. Two places where the text didn't name the error a retired layout gets: A, B.
- **Plan notes.** Phases 2 and 3 were one commit (the compatibility tests replay the vectors); the 137-byte guard guards the ciphertext bound; the testing kit now refuses unknown operations. No new residual: plan 026 removes three.
- **Course.** Updated under the new preserve-and-mark rule of `maintain-course`: `team-state` and the base-mode OPRF are kept as retired sections; `learning/` is local and not reviewed here.
- **Not checked:** the browser adapter beyond its tests; races between devices.

## Findings

### A. §3.8 step 3 doesn't name a transfer entry that doesn't decode

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text (done).
- **Where:** §3.8 step 3 listed a list out of order, a key of the wrong size and a short floor hash. An entry in the layout before D-66 is refused because the body doesn't decode (`MALFORMED_RECORD`, `transfer.v1.json` "an entry in the retired layout"), which the step didn't say.
- **Fix:** "It refuses a list that doesn't decode (an entry in the layout before D-66 included), out of order, …".

### B. A bundle longer than 104 bytes is `MALFORMED_RECORD`, not `DECRYPTION_FAILED`

- **Kind:** spec → code, wrong claim. **Severity:** low. **Disposition:** correct the text (done).
- **Where:** D-66 and §4.3 said a bundle of another length doesn't open, `DECRYPTION_FAILED`. The parser bounds `wrappedKeys`' ciphertext at 104 + 16 bytes (`member-keys-wrap.ts`, `SIZE + tag`), so the 137-byte layout is refused at the shape step (§8 step 2), before any decryption; review 026's guard notes say the same. In a list both are absent, so nothing behaves differently.
- **Fix:** §4.3's reader checks start with the ciphertext bound (`MALFORMED_RECORD`); D-66 names both outcomes.

## Edits ready now (no decision)

A, B: done after this review.

## Stop rule

Nothing here is for the action rule to fix, and no finding is open: by the letter, still **2 of 2** (reached at 036 and 037; 038 to 040 found nothing to fix). But plan 026 changed two formats and the roots of trust after the last `adversarial` review (037), and 039 and 040 were run in this session. Recommended before the formal model: a short fresh-context `adversarial` review of D-66 (who can now produce the floor, the local anchor and a transfer entry, and what a new device trusts).
