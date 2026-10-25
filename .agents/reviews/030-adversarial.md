# Review 030: adversarial, ninth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `f4484b5` (after plan 021). Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 1 of 2: review 029 (`change`, plan 021) found nothing to fix, and left one edit (029-A).
- **Fresh-context reviewer.** It had the adversarial brief, the recent changes named (D-58's amendment, D-62, D-63), and a question about account-wide operations that fail, half-apply or report something false, and about operations that write before they check. It had no access to `.agents/`, `learning/` or history.
  - It found no critical or high finding.
  - It reproduced its F1 to F4 with throwaway tests and deleted them.
  - This session checked each candidate against the code and the ledger. Below, the reviewer's F-numbers map to A–G: F3 is A, F2 is B, F1 is C, F4 is D, F5 is E, F6 is F, and the contract gap the reviewer flagged as a claim no code delivers is G.
- **Pairs checked, nothing beyond accepted threats:**
  - A2 + A11: the server already does what both do.
  - A2 + A9: TH-49 and TH-50; a forged state above the tip is handled by D-63 at the re-key.
  - A2 + A4: TH-50; a refused floor `replace` keeps an older floor, which SP-07's assumptions accept.
  - A2 + A6 (TH-38); A7 + A11 and A8 + A11 (TH-45, TH-11, TH-41).
  - A2 with a relayed link, anchor or transfer: TH-04, TH-21, TH-23, TH-39, TH-49.
- **Dropped:** the reviewer's F7, a session deleting the recovery wrap of an account with no PIN. It is TH-45's accepted residual (seen, and undone by a support restore, SP-26).
- **Not checked:**
  - the cc1 suite internals, streams and drafts;
  - the browser adapter and `takeLinkKey`;
  - vectors and the canonical encoding;
  - link and inbox clients in detail;
  - timing.

## Findings

### A. A phrase replacement and `secureAccount` write first, then list the teams: one store error leaves them half done

- **Kind:** spec → code (writes before it checks). **Severity:** medium. **Actors:** A2 alone, or a transient store failure. **Disposition:** fix (small).
- **Where:**
  - `confirmRecoveryPhrase` (`vault.ts:218-223`) replaces the recovery wrap and clears the pending phrase. Only then does it list the teams to re-key (`teamsWithOldRecoveryKey`), and that list rethrows `STORE_ERROR` (D-58: "any error but `STORE_ERROR`").
  - `secureAccount` (`vault.ts:395-404`) rotates the account key, then lists the account's teams (`accountTeams`).
  - D-58's amendment and SP-26 promise instead that a phrase replacement "reports it failed, re-keying the others".
- **Evidence:**
  - Reproduced by the reviewer for `confirmRecoveryPhrase`. One `member-keys` read throws, and the call throws `STORE_ERROR`, which §9 says to retry. At that point:
    - no team has been re-keyed and no report comes back;
    - the old phrase is refused;
    - a retry gets `WRONG_CREDENTIAL`, because the pending phrase is gone.
  - `secureAccount`: read only.
- **Impact:** a user told to retry may conclude the replacement failed and discard the new phrase, which is now the only recovery phrase. Their teams keep the old recovery key until they re-key.
- **Fix:** list before writing. Each function lists its teams before its first write. Both the new phrase's public key and the account's teams are known before the commit, and `rekeyTeams` already catches errors per team. A store error while listing then writes nothing, and a retry works.
- **Budget:** small (two reorderings; no state, fallback or duty). **Product cost:** none.

### B. `createTeam` builds a team that can never verify when keys are already published for that id

- **Kind:** spec → code; the spec contradicts itself. **Severity:** low (availability, for one team id). **Actors:** A11 alone, if it can predict or see the team id before creation. Also any leftover `member-keys` record for that account and id, with no attacker. **Disposition:** fix (small).
- **Where:**
  - `createTeam` (`vault.ts:467-468`) numbers the keys with `nextMemberKeysVersion` (§5.9: one above the newest published), but `newTeamOps` (`member-custody.ts:163`) writes the roster entry with `memberKeysVersion: 1`. The commit succeeds; every open is then `key_mismatch`, and version 1's identity is used for good.
  - §6.3 step 1 says "`memberKeysVersion` 1", and §5.9 says one above the newest published.
- **Evidence:** reproduced by the reviewer; the code path read here.
- **Fix:** the roster entry takes the version the keys were numbered with, and §6.3 says "the next version (§5.9): 1 unless keys were published under the account". **Budget:** small (one field, one sentence).

### C. "The vault reports keys it didn't make" holds only for teams where it holds a wrap

- **Kind:** overclaim. **Severity:** medium (a guarantee the integration relies on, overclaimed). **Actors:** A11 alone. **Disposition:** accept and document.
- **Where:**
  - `teamsWithForeignKeys` (`recovery.ts:167-185`) goes through `accountTeams` only, the teams with a wrap that opens. Keys a session publishes under the account in any other team are never reported. That includes a whole team the session creates under the account, with its own keys as the owner's: an honest server accepts it, since the caller is the signer and holds the owner capability (rule 8).
  - TH-37, TH-47 and SP-12 say keys the vault didn't make "are reported".
- **Evidence (reproduced by the reviewer):** members joining that team see the account as its owner. The account's own `createTeam` on that id is `STALE_VERSION`. `warnings()` returns nothing.
- **Why accept:** a session acts as the user in the product: it can create a team and invite people as the user, whatever the keys. Listing every team where the account has published keys would need a store query across teams (a new port method). `secureAccount` with `teamIds` already reports a team the product lists for the user that has no wrap that opens (D-60).
- **Acceptance text:** TH-37, TH-47 and SP-12: reported "for the teams where the vault holds keys"; TH-37's Attack names a team created under the account; a Limit in SP-12. A ledger residual.

### D. The anchor advance's conflict path refuses a re-read `team-state` below the chain

- **Kind:** spec → code. **Severity:** low (availability; flagged as tampering). **Actors:** A2 alone. **Disposition:** correct the code.
- **Where:** after a conflict, `advanceAnchor` (`anchors.ts:90-93`) looks up the re-read anchor's hash in the chain. For a version below the chain's first record there is none, and it throws `chain_conflict`. §6.1 step 2 says a `team-state` below the first record "isn't followed".
- **Evidence:** reproduced by the reviewer: a replayed older revision below a fresh device's floor.
- **Fix:** check only an anchor at or above the chain's first record. One condition.

### E. `foreign-member-keys` also names a team the server withheld a record for

- **Kind:** wrong claim. **Severity:** low. **Disposition:** correct the text.
- **Where:** `VaultWarning`'s comment (`vault.ts:89-91`) and the using guide read it as session theft only. Since D-58's amendment, a withheld `member-keys` record also lands a team there. For a planted mismatched wrap, `secureAccount` reports the team failed, and only support repairs it (TH-20).
- **Fix:** the comment and the using guide: "… or the server didn't serve the account's published keys; a team `secureAccount` then reports failed needs support (TH-20)".

### F. `rekey-needed`'s action doesn't say to pass the phrase

- **Kind:** wrong claim (advice). **Severity:** low. **Actors:** an account-key holder with the session (A9, or A7). **Disposition:** correct the text. This is the accepted residual for TH-12 and SP-23: keys made without the phrase carry the recovery wrap's key, which that actor can rewrite.
- **Where:** `rekey-needed` compares each team with the stored recovery key, which an account-key holder can rewrite (D-56), and its action is `rekey`. A `rekey` without the phrase takes the recovery wrap's key, so following the warning moves the teams that still carry the real key to the attacker's.
- **Fix:** the using guide and the `VaultWarning` comment: answer `rekey-needed` with `rekey(teamId, { phrase })`, which takes the typed phrase's key (D-56).

### G. The server contract doesn't state the identity check D-58 relies on

- **Kind:** spec gap. **Severity:** low. **Disposition:** correct the text.
- **Where:** "refuse a record whose identity fields differ from the key it is written under" is in the integration guide only (`integration.md:56`), not in the scope's server rules. D-58's rotation, which re-wraps without fetching the published record, relies on it.
- **Fix:** scope rule 5, or a new sentence in rule 3: "store a record only under the key its identity fields name".

## Edits ready now (no decision)

D, E, F, G; with 029-A.

## Needs a decision

- **A:** list before writing, in `confirmRecoveryPhrase` and `secureAccount` (recommended).
- **B:** the roster takes the numbered version (recommended), with §6.3 corrected.
- **C:** accept and document (recommended).

## Stop rule

A and B are for the action rule to fix: **0 of 2**.
