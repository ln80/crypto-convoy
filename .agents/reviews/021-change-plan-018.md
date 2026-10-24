# Review 021: change, plan 018 (D-59, D-60, D-61)

Mode: `change`. Scope: the `docs/` changes of plan 018 (`5ea3f45`) and what they ripple into, against the code at `b95fdc6`. Read only.

## Checked

- **Baseline.** `npm run check:spec` passes; ledger 0 of 2, nothing open to fix; open, low: 011-A.
- **Properties → protocol.** SP-07 (joins and the no-bundle repair), SP-11 / SP-23 (listed teams reported failed), SP-25 (every setup needs a credential): each sentence traced to §5.6, §5.10, §5.11, §6.4, §6.8 and to `vault.ts` (`joinTeam`, `secureAccount`, `confirmRecoveryPhrase`, `recover`, `rekey`) and `recovery.ts` (`rekeyTeam`, `productTeams`, `rekeyTeams`).
- **Threats → mechanism.** TH-04 (re-joins, unproven re-keys), TH-05 (withheld re-keys), TH-45 (no credential-free setup through the vault), AS-06: each claim traced to code and to plan 018's tests.
- **Decisions → text.** D-59 to D-61 searched across `docs/`, `README.md`, the guides and `src/` comments (first setup, "takes none", `teamIds`, `rekey` with no bundle, `RECOVERY_NOT_SET_UP`).
- **Plan notes.** Plan 018's execution notes: the breaking onboarding change is in the README, the using guide and the Duties table.
- **Not checked:** the local course (`learning/`).

## Findings

### A. The key hierarchy's account setup omits the PIN

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** `docs/key-hierarchy.md:298` (step 4: "the user enters it back; only then … store the recovery wrap").
- **Fix:** "with the current PIN (D-61)".

### B. Two summaries lag behind their entries

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §12's `rekey` comment (the owner's anchor is "the root for the new floor", not also the repair for a team with no bundle, D-59); TH-04's index row ("limited to the join, and to an owner's repair anchor"), while the entry now also names a re-join on a device with no vault anchor and unproven re-keys.
- **Fix:** add "also with no bundle (D-59)" to §12; the index row names re-joins and unproven re-keys.

### C. `RECOVERY_NOT_SET_UP`'s meaning is narrower than its uses

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §9 ("Recovery must be set up before creating or joining a team"); `recover`, `rotate` and `secureAccount` answer it too when there is no recovery wrap (`vault.ts`, `rotation.ts`).
- **Fix:** "No recovery wrap at the current version: needed to create or join a team, and by every operation that takes the phrase (§5.4, §5.7, §5.10, D-35)."

### D. A join that finds keys checks the vault's anchor but not the floor

- **Kind:** spec → code. **Severity:** low (that branch writes nothing). **Disposition:** correct the code.
- **Where:** D-59 ("the newest bundle's floor, when it holds one"); `src/account/vault.ts` `joinTeam` (the branch with bundles verifies the invite and vault anchors only).
- **Fix:** add the newest bundle's floor to that branch's roots: one line, so the check means what D-59 says.

## Not found

- `joinTeam` with no bundle roots on the invite and vault anchors; with neither it is a first contact, as TH-04 now says.
- `rekeyTeam` with an owner's anchor and no bundle numbers from published records and replaces the vault anchor (`recordVaultAnchor(…, true)`).
- `secureAccount` validates `teamIds` before writing, and reports listed teams with no wrap that opens after the rotation.
- `confirmRecoveryPhrase` needs `currentPin` whenever there is no recovery wrap; `recover` answers `RECOVERY_NOT_SET_UP`.
- The onboarding change is in the README, the using guide, the Duties table and the package smoke test.

## Edits ready now (no decision)

A, B, C (text) and D (one line of code, with a test).

## Stop rule

Nothing here is for the action rule to fix: **1 of 2**. A fresh `adversarial` review that finds nothing to fix makes the freeze candidate.
