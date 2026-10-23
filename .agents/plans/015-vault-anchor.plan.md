# Plan 015: the vault's own anchor, and floors only where every root agrees (review 009 B, C; review 010)

## Context

Review 009 (`.agents/reviews/009-adversarial.md`): **B (high)** in a split layout, `secureAccount` carries a floor planted with the stolen account key, since the vault has no anchor; **C (medium)** after `secureAccount`, the server serves the retired account key version to a fresh device, which recovers into it. Both reproduced.

Review 010 (`.agents/reviews/010-design-plan-015.md`, design mode, fresh-context reviewer) checked the first proposal (a required vault anchor; a required new phrase) and found it doesn't close either: a failed verification keeps the planted floor (A); re-wrapped old bundles keep it and the server picks the newest (B); a new phrase closes one path of several (C); a local anchor alone can become a forged floor (D); the retry path and export fall back to the floor (E, F); a fresh device has no repair (G).

**Decisions (user):** all roots must agree (010 A, B, D, E, F); an anchor from an owner repairs a floor (010 G); for C, correct the limits and recommend, rather than require, a new phrase (revisiting the earlier choice).

## Design (D-54)

1. **The vault's anchor.** The vault keeps its own anchor per team in its half of local storage (`DeviceKeyStore`, its own label), apart from the sessions' anchors. It records the tip of every chain it verifies: at creation (version 1), at join, at an open in its context and at an export. It never moves down.
2. **Roots agree.** The vault's roots for a team are the newest bundle's floor and its own anchor. An open in the vault's context counts the vault anchor as a root too; an export verifies the chain from the roots and refuses (`TRUST_FAILURE`) when it fails; it no longer seals after a failed check.
3. **Floors.** A re-key (§6.8, `rekey`, and each team of `secureAccount`) writes a floor only from a chain that contains every root; if they conflict or the chain fails, the re-key fails (`TRUST_FAILURE`, the team reported failed) and nothing is written. The floor's advance on open and export follows the same chain. The fallback "else the current floor" (D-52) goes.
4. **Repair.** `rekey(teamId, { anchor })` and `secureAccount({ ..., anchors: { [teamId]: anchor } })` take an anchor an owner gives out of band (`team.inviteAnchor()`): it is then the only root, and the verified tip becomes the floor and the vault's anchor. This is how a device with no anchor, or a planted floor, is repaired.
5. **Rotation.** `secureAccount`'s rotation keeps each bundle's floor (no fetch); its re-keys then write verified floors, and a team whose roots disagree is reported failed, with the repair of rule 4.
6. **Retired versions (C).** No client rule closes a retired version served to a stateless or stale device, or restored by support: SP-11, SP-19, TH-05 and TH-12 say so, with an integration duty to reset other devices after `secureAccount`. The `foreign-member-keys` warning's action becomes `secureAccount`, not `rekey`. `secureAccount` with a `newPin` that opens the current PIN wrap is refused (`MALFORMED_RECORD`, one evaluation); a `newPhrase` is the recommended default in the guides.

## Phases (one commit each)

1. **Spec:** D-54 (D-50 and D-52 amended); §3.7, §5.11, §6.1, §6.4, §6.8, §12; SP-07, SP-11, SP-19; TH-05, TH-12, TH-20; integration and using guides; retired wording. Reviews 009 and 010, ledger.
2. **Code and tests:** ports (`DeviceKeyStore` vault anchor), `MemoryLocalKeyStore`, the IndexedDB adapter; `recovery.ts` (roots agree, owner anchor), `member-custody.ts` (vault anchor, export refuses), `vault.ts` (`rekey`, `secureAccount`, join, create, warnings, `newPin` check), `load.ts` (an extra root); tests for review 009 B and 010 A–G, and the guards.
3. **Notes:** execution notes, reviews and ledger.

## Execution notes

- **Port:** `DeviceKeyStore` gains `getVaultAnchor`, `setVaultAnchor`, `deleteVaultAnchor`; `MemoryLocalKeyStore` and the IndexedDB adapter implement them, the browser one under the new label `local-vault-anchor` (§1, §3.7). `VaultOptions.anchors` stays optional: the vault's anchor lives in its own half.
- **Roots, as built:** `loadChain` and `TeamSession.open` take extra roots; `openSession`, `exportBundles` and `currentOwners` pass the vault's anchor. `recordVaultAnchor` never moves it down, except when an owner's anchor rooted the chain (it then replaces a forged higher one). Export no longer catches `TRUST_FAILURE`.
- **Re-key, as built:** `rekeyTeam(..., ownerAnchor?)` verifies from `[floor, vault anchor]`, or the owner's anchor alone, and throws on failure; `verifiedFloor` and its fallback are gone, and so is `fromLocal`: `rekey`, `secureAccount` and `confirmRecoveryPhrase` share the rule. `rekeyTeams` takes owners' anchors by team.
- **Rotation** unchanged: it keeps each bundle's floor; a planted floor stays in the re-wrapped old bundle of a team that `secureAccount` reports failed, until the owner's-anchor repair.
- **C, as built:** `#refuseCurrentPin` opens the current PIN wrap with the new PIN before anything is written (skipped when the budget is spent); `foreign-member-keys` now says `secureAccount`; the limits of SP-11, SP-19, TH-05 and TH-12 and the guides say what remains.
- **Tests:** `account-rotation.test.ts`: a failed chain writes nothing; a planted floor fails `secureAccount` and an owner's anchor repairs it; the same with the server serving a forged chain matching the planted floor; the split layout (export refuses, `secureAccount` fails); a vault with no anchor (fails with an honest server; the owner's anchor repairs, replacing a forged vault anchor); a `secureAccount` PIN equal to the current one refused. Earlier tests now use a different PIN. `member-rekey.test.ts`: the warning's action. `indexeddb-local-key-store.test.ts`: the vault anchor's own label.
- **Guards:** removing the vault anchor from the roots, adding the floor to an owner's anchor, catching export's failure, not recording the vault anchor, dropping the PIN check, and not forcing the owner's reset each fail a test (bash arrays for the file list this time).
- **Checks:** `typecheck`, `npm test` (731), `test:browser` (10), `check:spec`, `build`, `test:package` pass.
- **Integration (doconvoy e2eev2):** a `DeviceKeyStore` written by the integration needs the three vault-anchor methods; `secureAccount` may now report teams `failed` on their roots, repaired with `rekey(teamId, { phrase, anchor })` from an owner's `inviteAnchor()`; offer a new phrase and a different PIN; reset other devices afterwards.
- **Left:** the local course (D-52 to D-54).

