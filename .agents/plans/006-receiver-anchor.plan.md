# 006 — Receiver takes the invite anchor

## Context

`vault.openTeam(teamId, { anchor })` pins a joiner's first open to the anchor carried by the invite link (§6.4, SP-07, TH-04). A team opened in another context (D-29) goes through `createTeamKeyReceiver(...).openTeam(ports, transfer)`, which has no such option: the receiving context's first contact with the chain falls back to trust on first use. Splitting contexts therefore weakened the invite's protection; doconvoy worked around it by opening the team once in the vault's context. "API must match custody": the receiver gets the same option.

`TeamSession.open` already takes an anchor; only the receiver's signature and the specs change. No record, label, vector or error changes.

## Execution

- **Branch:** `plan-006-receiver-anchor`, from `plan-005-simplify`. One commit per phase; gates as in the workflow guide.

## Phase A — Spec

- **D-29:** consequence: the receiving context takes the invite anchor on a first open, as the vault's context does, so a split layout keeps first-contact protection.
- **TH-04:** disposition: the invite anchor applies whichever context opens the team (§3.8, §6.4).
- **SP-07:** the invite anchor counts in either context; Verification adds the receiver case in `test/security/rollback.test.ts`.
- **Key hierarchy** (joining scenario): "on its first open, in the vault's context or a receiving one".
- **Protocol:**
  - §3.8 step 3: with an anchor (the invite link's), the session starts from it (§6.1); the anchor is decoded before the transfer is opened, so a malformed one (`MALFORMED_RECORD`, `UNSUPPORTED_VERSION`) leaves the receiver unused;
  - §6.4 step 2: name both calls;
  - §12: `openTeam({ store, anchors }, transfer, { anchor? })`.
- **Integration** (Key custody across contexts): pass the invite link's anchor to the receiver on a first open.

## Phase B — Code and tests

- `src/team/receiver.ts`: `openTeam(ports, transfer, options: { anchor?: string } = {})`; `decodeAnchor` before `used = true`; pass the anchor to `TeamSession.open`.
- `test/security/rollback.test.ts`: a receiving context refuses a chain without the invite anchor (`TRUST_FAILURE` `rollback`, session `unverified`) and accepts the team's own anchor (`pending`).
- `test/security/key-transfer.test.ts`: a malformed anchor is refused before the transfer is used; the same receiver then opens it.
- README: the split-context example shows `{ anchor }` on a first open; the invite recipe names both calls.

## Verification

`npm run typecheck`, `npm test`, `npm run check:spec`, `npm run build && npm run test:package`.
