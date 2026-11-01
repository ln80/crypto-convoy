# Review 043: residuals

Mode: `residuals`, the first of its kind. Scope: the ledger's residuals table (42 rows), the threat model's accepted and partly mitigated dispositions, the deferred mechanisms of the [hardening direction](../guides/direction.md#deferred-mechanisms), and what `scope.md`, `integration.md` and `using.md` tell an integrator, at `836270e`. Read only, except the edits listed below, applied after it.

## Checked

- **Baseline.** `check:spec` passes; no finding open; the stop rule at 2 of 2 (040, 041), formal models done (plan 027, review 042).
- **Each residual's reason**, against the decisions since it was accepted (D-54 to D-66). Every reason still holds. The rows written before D-66 that named `team-state` were rewritten by plan 026; the TH-46 row says it is retired. No row rests on a rule a later decision removed.
- **Each revisit condition**, against the decisions and the one integration, doconvoy (`feat/e2eev2`). One has happened: A. The deferred decisions the others wait for (D-09, D-11, D-20, D-32) are still deferred; no hybrid suite, threshold OPRF, multi-owner approval or key transparency was added.
- **Chains**, pair by pair within each actor's rows, then across groups. Most chains stay inside one group and give no more than the group's worst row (owner compromise: TH-17 with 037-A and TH-38; server-controlled history: the TH-04, TH-05, TH-20 rows; restores: TH-36, TH-48, SP-19). No chain one actor can run alone reaches content or keys. One availability chain a session runs alone isn't written down: E.
- **Groups.** The server-controlled history group holds 13 of the 42 rows and grew at almost every `adversarial` review: B.
- **Disclosure** (before a freeze): for each residual an integrator or user must know, a sentence in `scope.md`, `integration.md` or `using.md`. Missing: what a malicious server can still do, in one place (C), and replacing inboxes after a removal (D).
- **Not checked:** whether doconvoy rotates OPRF key ids or caps evaluations per key id (the TH-09/TH-51 row's revisit); its support restore authentication (TH-48); the residuals of `formal/README.md`'s "Not covered" lists (they are coverage gaps, kept in the [audit brief](audit-brief.md), not accepted risks).

## Findings

### A. TH-04's revisit condition has happened: the one integration sends invites through its server

- **Kind:** residual whose reason no longer holds for an integration. **Severity:** medium (one actor, the server, with an integration choice: it presents a forged team at every join, and a joiner then writes items under a key the server holds). **Actors:** A2. **Disposition:** decision needed (below).
- **Where:** the TH-04 row's revisit condition is "a product delivers invites only through its server". doconvoy's `frontend/app/src/e2eev2/CONTRACT.md` (Invitations): the owner's client sends `inviteAnchor()` with the invitation, "the server puts it in the email link's fragment", and "since this server sends the email, the anchor protects later devices, not the join itself, against this server". So in the one product, every join is a first contact against the product's server; SP-07's invite-anchor guarantee protects a member's later devices only.
- **Evidence:** read (doconvoy at `feat/e2eev2`). The integration guide states the condition correctly (`integration.md` §Invites: "when the link reaches them outside your server"); doconvoy chose otherwise and says so.
- **Options:**
  1. **Accept for v1, and give doconvoy an out-of-band check (recommended).** The anchor is already a fingerprint of the team: a version and its record hash. doconvoy shows the owner a short code computed from `inviteAnchor()` and the joiner the same code from the anchor in the link, to compare by voice or another channel; or lets the owner copy the link and send it themselves. No protocol change; the integration guide gains the recipe, and TH-04's row names doconvoy's choice. Cost: one integration screen and one guide paragraph. The code's length decides the server's forgery work (80 bits: 2^80 records).
  2. **Bring D-11 (key fingerprints) into v1.** A protocol change, `costly` in the [complexity budget](../guides/direction.md#complexity-budget): a fingerprint format, a verified-key store on each device, and a report when a verified key changes. It closes more than joins (B), but adds remembered state and a human step, which the direction asks to defer to a v2 project.
- **Recommendation:** option 1 now; option 2 as the first v2 project (B).

### B. The server-controlled history group keeps growing: a candidate v2 project

- **Kind:** residual group. **Severity:** medium (as A, its newest member). **Disposition:** report; record in the direction guide's group table.
- **Where:** 13 of 42 rows: TH-04 (three rows: join, repair anchor, re-join), TH-05, TH-38, TH-12/SP-19 (retired account version), TH-12/SP-23 (rewritten recovery key), TH-20 (five rows: planted floor, 022 A, 037 D, 037 E, 041 A) and SP-07/TH-46 (041 D). Reviews 013, 019, 020, 022, 037 and 041 each added one or two; each was accepted with a pointer, as the direction says, and none could be fixed without remembered state or a new root.
- **What a mechanism would retire:** owner fingerprints compared out of band (D-11) would close the first-contact rows and give the repair anchor an authenticated source; key transparency would also close split views (TH-38), withheld state (TH-05), and the retired account version. Together they are expected to retire most of the root rules: the vault's own anchor (D-54), the repair rules (D-59), and much of the floor's movement (D-48, D-52).
- **Product need:** A makes it one for doconvoy.
- **Fix (text):** the direction guide's group row lists the 13 rows' threats and notes that a product now needs it; future reviews add to the row, not the residuals table alone.

### C. No single place tells an integrator what a malicious server can still do

- **Kind:** missing disclosure. **Severity:** low. **Disposition:** correct the text, before a freeze.
- **Where:** `scope.md` ends its server contract with "it still can't read items or plant keys without clients detecting it, except where threat-model.md records an accepted risk". Neither guide names split views (TH-38) or withheld newer state (TH-05): "split view", "key transparency", "rollback" appear in none of `scope.md`, `integration.md` or `using.md`. The others are stated, but spread out: first contact (TH-04), a forged transfer on a relayed channel (TH-49), items rewritten with an old key (TH-50), PIN brute force by the OPRF key holder (TH-09).
- **Fix:** a short list in `scope.md`, after the server contract: "What a malicious server can still do", one line per accepted A2 risk with its threat id and what the integration can do about it (deliver links outside the server, compare codes, run the restore process). Six to eight lines; it points, it doesn't repeat.

### D. Replacing inboxes after a removal is not in the integration guide

- **Kind:** missing disclosure. **Severity:** low. **Disposition:** correct the text.
- **Where:** TH-30's remedy is to replace the inbox: inboxes keep their key pair (D-20), so a removed member who obtains new submissions from storage (with A1) opens them. `integration.md` §Leaving, removal and account deletion says what the server removes and that `reconcile` rotates, not that the team's inboxes should be replaced; `using.md`'s "Someone leaves" recipe neither.
- **Fix:** one bullet in each: after removing a member, replace the team's inboxes (`replaceInbox`) and send the new links, if former members must not read new submissions (TH-30, D-20).

### E. A session alone can leave an account with neither PIN nor phrase until support acts

- **Kind:** unwritten chain (availability). **Severity:** low. **Actors:** A11 alone. **Disposition:** accept and document.
- **Where:** a session alone spends the PIN budget (TH-08, TH-44: "a session alone only spends the budget") and garbles the recovery wrap's `wrappedAccountKey`, which makes the phrase read as wrong (TH-46, review 033). Each is accepted alone; together, the account unlocks only on a registered device, and the remedy for the second (a recovery setup with the PIN) waits for the budget to reset or for support. No content or key is gained; the session already acts as the user.
- **Fix:** TH-46's residual sentence gains "with the PIN budget spent too (TH-44), by a registered device, or support only"; its ledger row says the same.

### F. About twenty residuals sit in no group

- **Kind:** simplification (bookkeeping). **Severity:** none. **Disposition:** optional edit.
- **Where:** the direction guide groups four mechanisms; about twenty rows fit none, and two clusters recur: support restores (TH-28 032 F, TH-36, TH-45, TH-46 twice, TH-48: "the archive restores it", mechanism: restores the integration authenticates) and session theft (TH-11, TH-37 030 C, TH-45, TH-47: mechanism: ending sessions, or server-side credential checks). Naming them lets a future finding there be accepted with a pointer, as for the other groups.
- **Fix:** two rows in the group table. Leave the rest (TH-09, TH-18, TH-21, TH-23, TH-30, TH-32, SP-16, SP-18, TH-25), each its own reason.

## Edits ready now (no decision)

All done after this review: A with option 1 (the anchor code in the integration guide, TH-04 and the using guide's invite row; doconvoy's screen is its own work), B, C, D, E and F.

## Stop rule

A is a residual whose condition changed, in an integration, not a protocol flaw a review found: its fix is option 1's text and integration work, unless option 2 is chosen. The count stays **2 of 2**; choosing option 2 would make it a protocol change, with its own `design` and `change` reviews and a new count.
