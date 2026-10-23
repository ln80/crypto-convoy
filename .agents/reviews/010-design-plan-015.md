# Review 010: design, plan 015 (review 009 B and C)

Mode: `design`, with a fresh-context reviewer. Input: the proposal for review 009 B and C, before code, at `8c2a7d6`. Read only.

## The proposal

1. **B:** the vault keeps its own anchor in every layout (`VaultOptions.anchors` required), advanced whenever it verifies a chain (open, export, join, leave check); `secureAccount` verifies each new floor from it.
2. **C:** `secureAccount` requires `newPhrase`; open question: `newPin` too?

## Checked

- The reviewer got the proposal, `docs/`, `src/`, `test/` only, and read the code paths (nothing run). It found the proposal needed for B but not enough, and C's fix to close only the least-used path.
- **Not checked:** `session.ts` and `chain.ts` in full, `reconcile`'s interplay, the server contract and guides beyond grep, split views (TH-38).

## Findings

### A. A failed verification carries the planted floor

- **Kind:** forgeable input (fallback). **Severity:** high (with A2, the remedy carries the planted floor and reports the team re-keyed; without A2, a permanent loss of the team on new devices).
- **Evidence (read):** `src/account/recovery.ts:71-72` (`verifiedFloor(..., newest.floor, local ?? newest.floor)`) and `:84-90` (`return current` on `TRUST_FAILURE`); D-52 ("If the verification fails, the floor stays the current one"); tests that require it (`account-rotation.test.ts`). A2 serves a chain that doesn't contain the local anchor during `secureAccount`: verification throws and the planted floor goes into the new keys. D-52 added this fallback so a chain problem never blocks a re-key; against a planted floor it is the attack.

### B. Re-wrapped older bundles keep the planted floor, and the server picks the newest

- **Kind:** forgeable input. **Severity:** high.
- **Evidence (read):** `src/account/rotation.ts:38-42` re-wraps each bundle with its floor (D-52); `openBundles` takes the newest wrap the server lists, with nothing checking the list. A2 withholds the new bundle's wrap at the new version: the re-wrapped old bundle is the newest, with its planted floor. Re-flooring only the new keys doesn't close 009 B.

### C. A new phrase closes the least-used path; the retired version comes back by others

- **Kind:** wrong claim (SP-11, SP-19, TH-05, TH-12 limits), combined attack. **Severity:** medium.
- **Evidence (read):** the retired version's archived PIN wrap opens with an unchanged PIN (§5.4's common path); requiring `newPin` would block `secureAccount` when the budget is spent, which D-40 and TH-44 exist to avoid, and can't make it different without an evaluation of the old wrap. A device that last saw the retired version unlocks with its archived device wrap, no credential at all (`currentVersion` refuses only versions below what it saw). A support restore (D-42, TH-48) returns to a retired version with an honest server. There, the old bundles (keys the attacker has, planted floors) open again, and new keys made there are the attacker's; `foreign-member-keys` advises `rekey`, the harmful action. The limits say this "matters only if someone also holds that old key", which is `secureAccount`'s premise.

### D. Verifying from the local anchor alone lets a forged anchor become the floor

- **Kind:** forgeable input (made worse by the proposal). **Severity:** medium to high.
- **Evidence (read):** `local ?? newest.floor` doesn't require the chain to contain the floor; A9 or A7 writes a forged local anchor, A2 serves a matching chain during `secureAccount`, and the forged tip becomes the new keys' floor (D-51's problem back). With the vault and team pages in one origin, the browser adapter has one anchor slot per account and team (`indexeddb-local-key-store.ts:114-121`): a script in team A's page writes the root the vault uses for team B.

### E. The retry path verifies from the floor only

- **Kind:** forgeable input (fallback). **Severity:** medium.
- **Evidence (read):** `vault.rekey` calls `rekeyTeam` without `fromLocal` (`vault.ts:467`); §5.11 step 3 sends failed teams there. A2 makes a team's write fail; the user's retry carries the planted floor.

### F. Export seals the bundles after its own check failed

- **Kind:** fallback. **Severity:** medium.
- **Evidence (read):** `member-custody.ts:196-199` catches `TRUST_FAILURE` and still seals, planted floor included; a receiving context with no anchor trusts it.

### G. The lost-device case, and no repair path

- **Kind:** residual. **Severity:** medium.
- **Evidence (read):** a fresh vault has no anchor, and its first open or export adopts the planted chain. No API repairs a floor: `joinTeam` with an anchor on existing keys writes nothing (D-50), `rekey` verifies from the floor.

### H. Lower

- §5.5 gives `rotate` plus `rekey` as a remedy: it keeps the phrase (C) and verifies from the floor (B). A garbage vault anchor makes `leaveTeam` and floor advances fail on that device.

## Smallest rules (reviewer)

- **B:** `secureAccount`, and any `rekey` on a device holding an anchor, writes a floor only from a chain that contains every root the vault holds for the team (its floor and its local anchor, as an open, §6.1 step 1), and gives that floor to every bundle it writes, re-wrapped ones included (the rotation verifies first). If the roots conflict or the chain doesn't verify, the team is reported failed and nothing is carried; export refuses likewise. The vault's anchor can live in its own `DeviceKeyStore` half under its own label, not shared with team sessions. For a fresh device, an anchor from an owner per team (`rekey(teamId, { anchor })` or a `secureAccount` option), or a named residual.
- **C:** no client rule closes it for stateless or stale devices against A2 or a restore. Correct the limits (SP-11, SP-19, TH-05, TH-12), add an integration duty to reset other devices, change the warning's action on a retired version to `secureAccount`; optionally refuse a `newPin` that opens the retiring PIN wrap (one evaluation); make `newPhrase` the recommended default rather than required.

## Decided (user)

- **A, B, D, E, F:** all roots must agree: a floor is written only from a chain containing the floor and the vault's own anchor (kept in its `DeviceKeyStore` half); a conflict fails the team; export refuses likewise.
- **G:** an anchor from an owner (`rekey(teamId, { anchor })`, `secureAccount({ anchors })`) repairs a floor.
- **C:** correct the limits; `newPhrase` recommended, not required; the retired-version warning says `secureAccount`; a `newPin` that opens the current PIN wrap is refused.
- **H:** the §5.5 remedy points to `secureAccount`.

Plan 015 (D-54).
