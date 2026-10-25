# Review 036: change, plan 024 (D-54, D-58 amended)

Mode: `change`. Scope: the `docs/` changes of plan 024 (`af731fa`, with the D-58 and §4.1 device wording in `57ae728`) and what they ripple into, against the code at `632d86f`. Read only.

## Checked

- **Baseline:**
  - `npm run check:spec` passes.
  - Ledger: 0 of 2, nothing open to fix. Still open, low: 011-A; for the next `complexity` review: 026-F, 028-C.
  - Plan 024's checks pass: 782 tests, browser 10, fuzz 30, build, package.
- **Properties → protocol:** each changed sentence was traced to a § and to the code.
  - SP-07: the repair with an owner's anchor reaches this device's local anchor. §6.8 step 1, D-54, `rekeyTeam`.
  - SP-26: a PIN, recovery or device wrap that doesn't parse costs only that method. §4.1, D-58, `readWrap` and its callers in `vault.ts`, `recovery.ts` and `unlock-methods.ts`.
  - SP-16: an owner approved in the same rotation. §6.7, `#rotate`.
- **Threats → mechanism:**
  - TH-04: "every root, this device's local anchor included", against `rekeyTeam`.
  - TH-12: the server's replay of `wrappedRecoveryPublicKey` (§4.1).
  - TH-46: the remedy for a recovery wrap that doesn't parse, against the warning's action `beginRecoverySetup`.
- **Decisions → text:** D-54 and D-58 searched across `docs/`, `README.md`, the guides and `src/` comments. The searches covered:
  - "replaces every root", "inviteAnchor", "owner's anchor";
  - `deviceRegistered`, `status()`, `DEVICE_NOT_REGISTERED`, `PIN_NOT_SET_UP`;
  - "registers again", "only owner".
- **Spec → code:**
  - **`readWrap`:** it rethrows `UNSUPPORTED_VERSION` and `STORE_ERROR`, and gives `unreadable` for any other parse or context failure (§4.1).
  - **Unreadable PIN wrap:** `unlockWithPin` and `verifyPin` refuse it before any evaluation, and `#refuseCurrentPin` skips its check (D-58).
  - **Unreadable device wrap:** `#registration` registers a new device, and `status()` reports it unregistered.
  - **`rekeyTeam` with an owner's anchor:** it sets the local anchor only where the context has an `AnchorStore`, as the vault's does.
- **Plan notes:** no risk accepted on the plan's own. The two spec adjustments made while coding are recorded in the plan: the device registers again, and `secureAccount` refuses an unparsable recovery wrap as `WRONG_CREDENTIAL`.
- **Not checked:** doconvoy's unlock screens.

## Findings

### A. §5.4 doesn't say what an unreadable wrap gives at unlock

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §5.4 (`protocol.md:537-540`) gives the failures for a missing wrap only:
  - same device: "If the wrap is gone … `DEVICE_NOT_REGISTERED`";
  - PIN: "With no PIN wrap … `PIN_NOT_SET_UP`".

  §4.1's new paragraph and D-58 say what an unreadable one gives, but §5.4 is where an integrator looks.
- **Fix:**
  - Same device: "… or can't be read (D-58)".
  - PIN: "a PIN wrap that can't be read is `WRONG_CREDENTIAL`, before any evaluation".
  - Recovery: "one that can't be read is `WRONG_CREDENTIAL`".

### B. The using guide's `status()` line doesn't say what an unreadable wrap reads as

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** `using.md:95` lists `status()`'s fields only. Since D-58's amendment, two cases need saying:
  - A PIN or recovery wrap that can't be read reads as `set-up`, and `warnings()` names it.
  - A device wrap that can't be read reads as `deviceRegistered: false`, so the app should offer the PIN or the phrase, which registers the device again. Plan 024's integration note says this; the guide doesn't.
- **Fix:** one sentence after the `status()` line.

## Not found

- The repair reaches `secureAccount` with `anchors` too, since both go through `rekeyTeam`. TH-04, SP-07 and §6.8 step 1 agree.
- `listDevices()` still leaves out a device wrap that doesn't parse (D-58's list rule). Its own device then reads unregistered in `status()`, which is consistent.
- An unknown `v` or suite stays `UNSUPPORTED_VERSION` in every identity read (§10). The record-archive test covers the recovery wrap.

## Edits ready now (no decision)

A, B.

## Stop rule

Nothing here is for the action rule to fix: **1 of 2**. A fresh `adversarial` review (037) that finds nothing to fix makes the freeze candidate. It is planned with a different model, in Cursor.
