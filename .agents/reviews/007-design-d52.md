# Review 007: design, D-52 (the floor as the root of trust)

Mode: `design`, with a fresh-context reviewer. Input: the proposal for review 006 B and C, before code, at `3dc80a4` plus review 006 (uncommitted). Read only.

## The proposal

1. **Read (§6.1 step 1):** the newest bundle's floor always counts as an anchor; the chain is fetched from the lowest anchor and must contain every anchor.
2. **Re-key (§5.9, §6.8 step 1):** the new floor is the tip of the chain verified from the current floor alone.
3. **Rotation (§5.7 step 4):** each bundle keeps the floor it carries; nothing computed or fetched.
4. Creation, join and the §6.8 step 4 clean-up unchanged.

## Checked

- The reviewer got the proposal, `docs/` and `src/` only. It confirmed from the code that rules 1 and 2 close review 006 B and C, and listed what the proposal adds (the floor always read, a fetch from the floor, a fetch at each re-key, a re-key state "verified tip, at least the current floor"), removes (the `team-state` and local anchor as floor sources and their skip-if-unreadable fallback, the floor computation at rotation, D-50's "the floor never adds a download") and leaves (the local anchor and `team-state` still read).
- This session's pass agrees, and adds that the clean-up (§6.8 step 4) verifies the chain under rule 1 before it rewrites `team-state`, so it no longer carries a forged anchor to the newest key.
- **Not checked:** receiving contexts beyond their floor, the browser adapter, vectors (no layout change is proposed), measured sizes (the read cost below is estimated from D-34).

## Findings

### A. The read cost is the steady state, not an edge case

- **Kind:** spec cost, against three decisions. **Severity:** high as a cost; no security risk.
- **Evidence (read):** floors move at a join or a re-key only, while local and `team-state` anchors move at every rotation of the team. So nearly every open, on every device and context, fetches from the join version (version 1 for the creator) and runs the full chain check on every record since. D-48 ("Using the floor on every open … each time (D-34)"), D-50 ("Counting the floor on every open") and D-34 ("old rosters are downloaded only at first contact") rejected exactly this. At 1,000 members a record is about 360 KB: 50 versions since the floor is about 18 MB per open. It hits `TeamSession` loads and reloads, the vault's clean-up check and `currentOwners`.
- **Fix proposed:** keep rule 1 and bound it: when the vault opens a team (it has the account key) and the chain it verified from the floor has a tip above the floor, it rewrites the newest `member-keys-wrap` with that tip as its floor (a delete and a create of the same identity, in one batch). Safe for the same reason as rule 2: the tip is verified from the floor. Cost: one small write per vault open that saw a new version, like `advanceAnchor`'s; a receiving context gets the new floor at its next transfer.
- **Needs:** a decision.

### B. An account key holder can still plant a floor, and D-52 makes it last

- **Kind:** forgeable input. **Severity:** medium.
- **Evidence (read):** with the account key and a session (A9 in the vault, A7 with an unlocked vault, A8 with A11), delete the newest `member-keys-wrap` and create it again with the same keys and a forged floor: no new `member-keys` record, so D-43's foreign-keys report sees nothing. Under D-52 every device then fails (honest server) or new devices open a forged team (with A2), and rule 3 carries the planted floor through `secureAccount`'s rotation, where today's rotation would overwrite a planted floor lower than the real `team-state`. After the rotation the planted wrap exists only under the new account key version.
- **Fix proposed:** at `secureAccount` only, which §5.11 already requires to run from a device the attacker didn't control, rule 2 verifies from that device's local anchor when it has one, else from the floor. Cost: the guarantee rests on §5.11's precondition. Alternative: accept it in TH-20 and SP-07 (a leaked account key can plant a floor; `secureAccount` from a clean device that has opened the team is the remedy).
- **Needs:** a decision.

### C. A forged `team-state` blocks every device, and nothing heals it

- **Kind:** missing threat (availability). **Severity:** medium.
- **Evidence (read):** a `teamStateKey` holder (A9 in any context that holds the team, A7) writes a valid `team-state` with a forged anchor. Under rule 1 every open fails (`chain_conflict` or `rollback`). The re-key goes through (rule 2), but the clean-up and `advanceAnchor` need a successful load, so nothing rewrites it. TH-46 names only garbage (`state_unreadable`), and a valid forgery looks like a server attack, so support may not know to restore it.
- **Fix proposed:** (a) report it apart: a `team-state` anchor that the chain verified from the floor contradicts is `TRUST_FAILURE` with a new reason (for example `state_conflict`), and TH-46 covers it: support restores the previous revision. Fails closed, one new reason in §9. Alternative (b): overwrite it by compare-and-set on a `chain_conflict` at a version the floor-verified chain contains (never on `rollback`, which A2 can cause). Heals without support, but discards evidence of a split view (TH-38).
- **Needs:** a decision.

### D. A failed verification at a re-key is unspecified

- **Kind:** spec gap. **Severity:** low to medium (A2 or a planter could block the SP-12 remedy).
- **Fix proposed:** rule 2 ends "else the current floor": the floor never moves to unverified data, and no chain problem blocks a re-key.
- **Needs:** an edit, with the decision.

### E. Floors fall further behind

- **Kind:** stale text, residual. **Severity:** low.
- **Evidence (read):** with rule 3, rotations no longer move the floor; the TH-05 window for a new device whose `team-state` is withheld goes back to the last re-key or join (version 1 for a creator who never re-keys). SP-07 ("moved forward at each re-key and account rotation"), §4.3 and §5.7 step 4 need rewording. A's fix closes the gap.
- **Needs:** an edit; A closes it.

### F. The server can make an older genuine floor the root

- **Kind:** residual. **Severity:** low (within TH-05).
- **Evidence (read):** A2 withholds the newest wrap or replays archived ones, so an older genuine floor is the root; a re-key then can write a floor below the newest one. After a support restore, replayed wraps can bring back a floor planted earlier (TH-48).
- **Fix proposed:** accept within TH-05 and TH-48; say so in SP-07's assumptions.
- **Needs:** an edit.

## Smallest rule (reviewer and this session agree)

Rules 1–3 with D's "else the current floor". Rule 1 can't get cheaper without losing the guarantee: local and `team-state` anchors can be rewritten at any time, so each open must link them to the floor with owner checks. A's floor advance on vault opens is what keeps the cost near today's. A cheaper, weaker variant counts the floor only on a device with no local anchor; it leaves the tampered device itself open to B, with A2.
