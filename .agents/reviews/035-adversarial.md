# Review 035: adversarial, eleventh round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `e63c839` (after plan 023). Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 1 of 2: review 034 (`change`, plan 023) found nothing to fix.
- **Fresh-context reviewer.** It got the adversarial brief and had no access to `.agents/`, `learning/` or history. The brief named the newest rules: D-56 amended, D-64, D-65 and the owner refusals. Results:
  - no break of confidentiality or integrity, by one actor or by two;
  - four candidates about availability and misleading reports;
  - F1–F3 reproduced with throwaway tests, which it deleted.
- **This session's checks.** I read F1's code path (`recovery.ts:140-152`, `load.ts`). I checked F2, F3 and F4 against the code paths the reviewer quoted.
- **Found sound:**
  - D-64's apply path, which drops only stale approvals and keeps held keys;
  - the D-56 typed-phrase paths, which never sign with or carry the stored key;
  - the order of the chain, transfer, item and inbox checks;
  - D-58's list filtering.
- **D-65 under a server rollback** is reproduced and stays within SP-16's Limit, so it is not a finding.
- **Pairs checked, with nothing beyond accepted threats:**
  - A2 + A11 (same as A2);
  - A2 + A9 (TH-49, TH-20);
  - A2 + A4 (TH-05, TH-50);
  - A2 + A6 (TH-38);
  - A7 + A11 (TH-45);
  - A8 + A11 (TH-11, TH-41);
  - A2 with a relayed link or transfer (TH-04, TH-21, TH-23, TH-49).
- **Not checked:**
  - the browser adapter;
  - stream internals;
  - OPRF, Argon2id and the cc1 suite code;
  - base64url canonicality;
  - vectors;
  - races between devices.

## Findings

### A. The repair with an owner's anchor leaves this device's local anchor, so the device stays `unverified`

- **Kind:** spec → code, wrong claim.
- **Severity:** medium. One actor, after an accepted first contact. The documented repair doesn't repair, though the failure shows.
- **Actors:**
  - A2 alone, through a forged chain served at a join without an invite anchor (TH-04);
  - or A9, by writing the local anchor.
- **Disposition:** fix (small).
- **Where:**
  - With an owner's anchor, `rekeyTeam` (`recovery.ts:140-152`) uses that anchor as its only root and replaces the vault's anchor.
  - But the device's local anchor (`LocalKeyStore`) stays a root for every open (§6.1 step 1, `load.ts:26-34`). That covers `openTeam`, export and `leaveTeam`'s chain check.
  - TH-04 and SP-07's assumptions say the owner's anchor "replaces every root".
- **Evidence:** reproduced by the reviewer.
  1. dave joins a forged version 1 and opens it, which stores the forged local anchor.
  2. The server turns honest.
  3. dave runs `rekey(teamId, { phrase, anchor })`.
  4. `openTeam` is `chain_conflict`, also after a second repair.
  5. Only clearing local storage recovers the device.
- **Fix:** the repair with an owner's anchor also replaces this device's local anchor with the new floor. That is the same `replace` as for the vault's anchor.
  - Other contexts keep theirs. A receiving context gets a new transfer anyway (§3.8), and other devices reset or repair the same way.
  - **Budget:** small (one write; no new state).

### B. One private wrap that doesn't parse makes status, warnings and the phrase repairs fail

- **Kind:** spec → code (D-58's rule is applied to lists only).
- **Severity:** medium. One actor; the reports a user relies on under attack fail.
- **Actors:** A11 alone (`replace` on the account's private records).
- **Disposition:** fix (small).
- **Where:** `fetchWrap` (`unlock-methods.ts:44`) parses the record it reads by identity, and throws when the record doesn't parse.
  - **A PIN wrap that doesn't parse:**
    - `status()` and `warnings()` throw `MALFORMED_RECORD`, which hides every warning while a session thief is active;
    - `changePin(newPin, { phrase })` and `secureAccount` with `newPin` (`#refuseCurrentPin`) are refused;
    - `recover` throws after unlocking.
  - **This device's own device wrap that doesn't parse:** `recover(phrase)` fails too, because `#registration` parses it.
  - **A recovery wrap that doesn't parse:** `status()` throws, although D-56's amendment covers `warnings()`.
- **Evidence:** reproduced by the reviewer.
- **Fix:** D-58 and D-56 extended. A private wrap the vault reads by its identity, and that doesn't parse, counts as present but unreadable:
  - `status()` reports that method as set up;
  - `warnings()` names it: `pin-not-set-up` for the PIN, with action `changePin`, and `recovery-key-mismatch` for recovery, below;
  - the operation that writes that method replaces the live record without reading it. That means `changePin`, `#refuseCurrentPin` (no check is possible there, so it is skipped, as for a spent share), and the device registration in `recover`.
  - **Budget:** small (one reader shared by the PIN, recovery and device wraps; no new state).

### C. For a recovery wrap that doesn't parse, `recovery-key-mismatch` points to an operation that can't succeed

- **Kind:** wrong claim (advice). **Severity:** low. **Actors:** A11. **Disposition:** correct the code.
- **Where:**
  - `warnings()` gives action `secureAccount` (`vault.ts:476`). But `secureAccount` checks the phrase by opening the wrap, so it refuses a wrap that doesn't parse. TH-46 gives the right remedy: a recovery setup with the PIN.
  - Also, `storedRecoveryKey` counts `UNSUPPORTED_VERSION` as unreadable. So a recovery wrap a newer library wrote reads as a mismatch to an older one. Readers ship first, so that client should report `UNSUPPORTED_VERSION` instead (§10).
- **Fix:**
  - A recovery wrap that doesn't parse gives `recovery-key-mismatch` with action `beginRecoverySetup`. One whose key can't be read keeps `secureAccount`.
  - `UNSUPPORTED_VERSION` is rethrown.

### D. `setOwners` names an owner who holds nothing, if the same rotation approves it

- **Kind:** spec → code. **Severity:** low. The owner chose it explicitly, so there is no security effect. **Disposition:** correct the text.
- **Where:**
  - §6.7 step 1 says "New owners must hold version n", and §12 says "not holding the version: `MALFORMED_RECORD`".
  - `#rotate` accepts an owner who is approved in the same rotation, and so does `versionOp`.
- **Evidence:** reproduced by the reviewer. `setOwners(["alice", "carol"], { approve: [carol] })` with carol pending gives carol an owner and `ready`.
- **Fix:** §6.7 and §12 say "hold version n, or have keys approved by the same rotation". This is what the code does, and it saves a rotation.

### E. The server can replay an earlier `wrappedRecoveryPublicKey` of the same version

- **Kind:** wrong premise (text). **Severity:** low. **Actors:** A2. **Disposition:** correct the text.
- **Where:** `wrappedRecoveryPublicKey`'s associated data binds the account and the version, not the wrap's `wrappedAccountKey` (`account-key-wrap.ts:51-54`). So after a phrase replacement at the same account key version, the server can serve the old field in the new wrap.
  - Keys made without a phrase then carry the old phrase's key.
  - A holder of the old phrase, with the server, could already open the archived old wrap, so nothing is gained.
  - §4.1 and TH-12 say only an account-key holder can rewrite the field.
- **Fix:** §4.1: "… or the server, replaying an earlier one of the same version, which gives nothing a holder of the old phrase doesn't have (TH-36)".

## Edits ready now (no decision)

C, D, E; with 034-A, 034-B.

## Needs a decision

- **A:** the owner's-anchor repair replaces this device's local anchor too (recommended).
- **B:** a private wrap read by identity that doesn't parse counts as present but unreadable (recommended).

## Stop rule

A and B are for the action rule to fix: **0 of 2**.
