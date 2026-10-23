# Review 003: threat model, properties and protocol, round 3

Scope: all of `docs/` and the matching `src/` at `42d6b88` (after plan 008), reviewed with the [spec-review](../workflows/spec-review.md) workflow. Discussion first: nothing here is planned yet.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries outstanding. Last review: 002 (plan 008).
- **Properties → protocol.** Every non-deferred property (SP-01…SP-12, SP-14…SP-19, SP-21…SP-23, SP-25, SP-26), sentence by sentence. Overclaims found: SP-15 (finding C), SP-12 / D-43 (finding D).
- **Threats → mechanism and code.** Every mitigated or partly mitigated threat; for the "refused with" claims, the code paths in `src/team/chain.ts`, `access.ts`, `anchors.ts`, `load.ts`, `membership.ts`, `owner.ts`. Understated: TH-05, TH-46 (A), TH-14 (G), TH-47 (D).
- **Actors × operations.** A2, A6, A7/A9 (open vault), A8, A11 against §12, plus the support restore (D-42), which no actor list covered (F).
- **Decisions → text.** D-39 to D-44. Stale or wrong procedure text: key-hierarchy "Restoring an account" and "Who can open what" (B), §5.11 and key-hierarchy "Losing a device" on owners' re-keys (E).

## Findings

### A. A withheld or deleted `team-state` silently sends a new device back to first contact

- **Kind:** understated residual, overclaim. **Severity:** high: a server alone can serve a forged team to an existing member's new device.
- **Where:** `docs/key-hierarchy.md:153` ("A new device starts from that anchor instead of trusting the server on first use"); TH-05 (only "an older `team-state`"); TH-46 (only garbage, not deletion); §4.4 ("no record means no anchor"); `src/team/anchors.ts` `readServerState` returns `null`, `src/team/load.ts` then verifies from version 1 with no anchor.
- **Evidence:** a new device has no local anchor. If the server (A2) omits the account's `team-state`, or a session thief (A11) deletes it (archived, but no longer served), `loadChain` runs first contact. A2 can then present a forged chain whose roster seals a team key of its own to the member's public keys and whose owners are forged `member-keys` records: the member is `ready` and writes new items under the server's key. TH-04 lists "a device with no stored state" in its attack, but nothing says an existing member's every new device is in that case at the server's choice, and nothing reports it.
- **Options:**
  1. Edit only: state it in TH-04/TH-05/TH-46 and fix key-hierarchy:153; recommend that integrations hand an existing device's anchors to a new one out of band (`openTeam(teamId, { anchor })` already takes one).
  2. Protocol: make the absence detectable. For example, the `member-keys-wrap` carries an anchor floor (written at team creation, join with an invite anchor, re-key and account rotation, all of which already rewrite or write it), and §6.1 adds it to the anchors. Cost: a layout change of `member-keys-wrap` (unreleased, so allowed), vectors, one more anchor source. Leaves a member who joined without an invite anchor and never re-keyed or rotated on first contact.
- **Needs:** a decision.

### B. Remedies for a leaked recovery phrase loop back to the leaked phrase

- **Kind:** wrong procedure. **Severity:** high for users who follow it.
- **Where:** `docs/key-hierarchy.md:346-352` (Restoring an account, step 2), `:274` and `:279` (Who can open what), `docs/using.md:122` (no row for a leaked phrase), §5.11 (intro names a leaked PIN only).
- **Evidence:** a restore (D-42) brings back the version from before the takeover, whose phrase is the one the thief used when the takeover was done with the phrase (TH-11, TH-41). Step 2 then says "secures the account (§5.11)", but `secureAccount` and `rotate` keep the phrase (D-41): the thief can do it all again. In "Who can open what", the phrase rows disagree with each other (one says rotate, the other approve by hand and no rotation), and neither re-keys before rotating. The right order today is: end the account's other sessions, replace the phrase (`confirmRecoveryPhrase` with the old phrase), then `secureAccount` with the new phrase. That re-keys every team twice, the first time with proofs the thief can also make.
- **Options:**
  1. Edit: write that procedure in all four places.
  2. Small API addition: `secureAccount({ phrase, newPhrase?, newPin? })` rotates, replaces the phrase and re-keys once, proven by the old phrase. Cost: one optional input, one test; removes the double re-key.
- **Needs:** the edit now; option 2 is a decision.

### C. Roster entries aren't checked against published member keys

- **Kind:** overclaim (SP-15). **Severity:** medium: it weakens the only defence against TH-17, which is detection.
- **Where:** SP-15 ("the accounts added, removed or re-keyed"; "a report names the account the key belongs to" holds for owners only); §4.5 reader checks 4–5 (owners only); `src/team/chain.ts` `verifyChain` checks owner entries against `memberKeys` and reports every roster diff unchecked.
- **Evidence:** a stolen owner key (A6) can sign a rotation whose roster has `{ accountId: "alice", memberKeysVersion: 99, keysHash: H(attacker keys) }`. With an honest server, no such `member-keys` record exists (rule 8), yet every member's client reports "alice re-keyed" instead of a new account, and `team.members()` lists alice. Alice's own client only goes `pending` (or `key_mismatch` if the version number matches one she holds).
- **Fix proposed:** §4.5 check 4 extends to every roster entry of records newer than the highest anchor: a published `member-keys` record of that account and version, with that `keysHash`, else `TRUST_FAILURE` (`key_mismatch`). `loadChain` already fetches every `member-keys` record of the team, so it costs no request, only one hash per entry. A server that hides records could already deny service.
- **Needs:** a decision (small).

### D. Bait keys starve a member's approvals while the thief keeps a session

- **Kind:** overclaim (D-43 Consequence "can't block a member", SP-12 "never block the member's own keys", TH-47 "mitigated"). **Severity:** medium.
- **Where:** §6.5 step 3 and `src/team/owner.ts` `#reviewedKeys` (only the newest published keys can be approved); `src/team/membership.ts` `overviewOf` (proof computed on the newest keys only).
- **Evidence:** after the member's join or proven re-key at version k, a session thief publishes k+1. The member's keys are no longer the newest: `reconcile` sees an unproven re-key, and `approve` of k is `STALE_VERSION`. Each new member re-key is outpaced again. Writes aren't blocked, approvals are. The remedy, ending the thief's sessions, is stated in §5.11 only.
- **Options:**
  1. Edit: TH-47, SP-12 and D-43 say it holds once the integration ends the thief's sessions (as §5.11 already requires); the member's warning tells them to.
  2. Change: `reconcile` approves the newest **proven** keys even when newer unproven keys exist. Breaks "an approval is for the newest keys" and adds a rule; not recommended.
- **Needs:** the edit; option 2 only if you want it.

### E. An owner's own re-key: the spec says "another owner", the code lets the owner approve it

- **Kind:** wrong claim, missing guidance. **Severity:** medium: after `secureAccount`, the attacker's copied owner key still owns the team until the re-key is approved.
- **Where:** §5.11 last paragraph ("another owner approves by hand"), key-hierarchy `:334` ("waits for another owner"), SP-23 Limit; `src/team/owner.ts` `approve` and `rotate` accept the caller's own handle (signed with the previous key, §4.5 check 5); `test/security/member-rekey.test.ts` "an owner's own approval is pinned too" shows it.
- **Evidence:** read literally, a single-owner team never completes `secureAccount`. For any owner, the fastest safe step is to approve their own re-key from the clean device right away: those are keys their vault made, so no out-of-band check applies, and it replaces the owner key the attacker copied.
- **Options:**
  1. Edit: the owner approves their own re-key at once (`owner.approve([ownHandle])`); another owner may do it too. Add a test.
  2. Change: `secureAccount` (or the next `openTeam` of an owner) does that self-approval itself. Cost: the vault opens each owned team's session; closes the window without integration code.
- **Needs:** a decision between 1 and 2.

### F. Missing threat: the support restore is an attack surface

- **Kind:** missing threat. **Severity:** medium.
- **Where:** SP-26 Limit ("the library doesn't check who asks"), scope rule 7, D-39, D-42, integration guide `:69-70`.
- **Evidence:** support can restore an older account key version or a single wrap. Someone who knows a replaced credential (A8 with the old PIN or phrase), or holds a revoked device (A7), can ask for the generation that their credential opens. A2 or an insider can also revive archived wraps (for example a revoked device's) without a request. No threat names this; the archive window makes it a lasting option.
- **Fix proposed:** a new threat, accepted: restores are the integration's to authenticate (not by the session or a credential the request could involve); after a restore, the user secures the account and replaces any credential that may be known (B). Bounded by the restore window.
- **Needs:** an edit (new TH id, its index row, SP-26 Related threats).

### G. A server listing a removed member as active keeps them in

- **Kind:** understated (D-31, TH-14). **Severity:** low: SP-22's Limit says it.
- **Where:** D-31 Consequence ("can only cut access … Removed members stop receiving new versions at the next owner session, not at an integration's discretion"); TH-14 (actor A4 only).
- **Evidence:** `reconcile` keeps any holder in `activeAccountIds`. A2 together with A4 keeps the removed member reading new items; nothing changes in the roster, so no report.
- **Fix proposed:** TH-14 names "A4 with A2" in its residual and cites SP-22's Limit; D-31 says "never add a reader; it can keep one it should remove". Owners' overview already shows each holder as `active`.
- **Needs:** an edit.

### H. TH-36 omits a garbage rotation

- **Kind:** incomplete attack. **Severity:** low: SP-26 already covers retirement.
- **Where:** TH-36 Attack lists change PIN, replace phrase, revoke device.
- **Evidence:** a session can also commit `setAccountKeyVersion` with garbage wraps, which retires every real wrap at once; the version restore undoes it.
- **Needs:** an edit.

### I. Code: the anchor retry rereads `team-state` with one bundle only

- **Kind:** spec → code (plausible, not reproduced). **Severity:** low.
- **Where:** `src/team/anchors.ts` `advanceAnchor`, on `StoreConflictError`: `readServerState(…, [bundle])`, while the first read uses every bundle.
- **Evidence:** if another device wrote the state under another bundle's `teamStateKey` (around a re-key and its clean-up, §6.8 step 4), the retry fails with `state_unreadable` where §6.1 step 7 expects a reload. Needs a test to confirm.
- **Needs:** a fix and a test if confirmed.

### J. After a phrase replacement, a failed team's retry can't be proven

- **Kind:** spec → code, found while designing B option 2. **Severity:** low.
- **Where:** §5.6 and §5.11 step 3 (retry "with the re-key of §6.8"); `src/account/vault.ts` `rekey` checks the phrase against the account's **current** recovery key.
- **Evidence:** after `confirmRecoveryPhrase` or `secureAccount` with a new phrase, the retry must use the new phrase, but the team still holds keys carrying the old recovery key, so the proof never verifies: an owner approves by hand. The old phrase, which would prove it, is refused (`WRONG_CREDENTIAL`). Now stated in §5.11 and D-45; not changed.
- **Needs:** a decision, if worth it: let `rekey` sign with the phrase whose recovery key the team's held keys carry.

## Validated, then done (this round)

Each finding was first reproduced with a throwaway test against the code: B (the restored phrase reopens the account after `secureAccount`), D (bait after each proven re-key keeps `reconcile` and `approve` from approving it), F (a restored revoked device wrap unlocks), G (an active list naming a removed member rotates nothing), H (a session's version switch with no real wraps locks the account; the version restore undoes it). Then:

- **B:** option 1 and option 2. D-45: `secureAccount({ phrase, newPhrase?, newPin? })` replaces the phrase in the same pass, proofs by the current phrase. §5.7, §5.11, §12, D-36, TH-11, TH-41, SP-11, SP-26, key hierarchy (Who can open what, Replacing the phrase, Restoring), using guide, integration guide. Tests: `secure-account.test.ts` (new phrase; refusals before any write), `record-archive.test.ts` (phrase thief's takeover restored, then secured). Both fail with the old recovery wrap.
- **D:** TH-47 is now partly mitigated, SP-12 gains a Limit, D-43 Consequence; test in `member-rekey.test.ts`.
- **F:** TH-48 (accepted), SP-26 Limit and Related threats, scope (integration duty), integration guide; test in `record-archive.test.ts`.
- **G:** TH-14 residual, D-31 Consequence.
- **H:** TH-36 Attack; test in `record-archive.test.ts`.

## Decided

- **A: anchor floor in the member keys bundle** (to plan). Set at team creation (version 1) and at join (the invite anchor, which moves from `openTeam` to `joinTeam`), carried forward by re-keys and account rotations, and carried in transfers; §6.1 counts it as an anchor. Layouts of `member-keys-wrap` and of transfer bundles change (unreleased).
- **C: done (D-46).** §4.5 check 4 covers every roster entry; SP-15, TH-17; `verifyChain`; `team-key.v1.json` regenerated with two cases (seals are randomised, so every sealed entry and hash changed; no other vector depends on them); test in `change-visibility.test.ts`. The test and the vector case fail with the check weakened.
- **E: done (D-47).** `reconcile` self-approval. The calling owner's `reconcile` approves its own re-key when the session holds those keys' private half (newest published keys equal one of its bundles); anything else stays `owner-rekey` for a human. Validated first: self-approval already works through `approve`, signed with the previous owner key, in a single-owner team too. Spec: SP-22, SP-23, SP-10 verification, §5.6, §5.11, §6.8, §6.9, D-31, D-33, TH-41, key hierarchy, using guide. Tests: `reconcile.test.ts` (own re-key approved; keys published by someone else and another owner's proven re-key left to a human), `secure-account.test.ts` (single owner; the copied owner key is refused after), the `reconcile` property. Removing self-approval, or ignoring possession, fails them.

## Need a decision

- I: confirm with a test, then fix.
- J: proven retries after a phrase replacement.

## Not found

No divergence in the confidentiality and integrity properties (SP-01 to SP-06, SP-14, SP-17, SP-18, SP-21), the credential rules (SP-08 to SP-11, SP-25) or `reconcile`'s rules (SP-22, SP-23) beyond the points above.
