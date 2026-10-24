# Review 023: design of plan 019 (D-62)

Mode: `design`, with a fresh-context reviewer. Input: plan 019's first design, at `fef5f80`. Read only. Each finding was checked against the code; A to F were taken or answered in plan 019 and D-62.

1. **A. Nothing is lost to the server or a session** (none). The server could already withhold `team-state`; garbage now causes a replacement instead of a stop. *Corrected premise:* `team-state` still bounds rollback above the floor for a context with no local anchor, when it opens; D-62's consequence says so.
2. **B. The compare-and-set needs the revision** (spec gap, medium). An absent state returned as null would loop on conflicts and never be replaced. *Taken:* `readServerState` returns the revision with no anchor; the advance compares only a readable anchor and skips the `chain_conflict` check for an unreadable one.
3. **C. Two contexts could overwrite each other** (hardening, medium): a context holding older keys and the vault, each unable to read the other's write. *Taken:* only keys the tip's roster holds replace an unreadable state (the clean-up's existing test); a test shows the older context leaves it alone.
4. **D. A narrower alternative** (simplification): replace `team-state` only in the repair with an owner's anchor. *Rejected* in D-62: garbage from other causes would still stop every device until a user acts.
5. **E. The floor test reads the newest bundle** (spec gap, low). *Taken:* §6.1 step 1 and D-62 say "the newest bundle holds a floor".
6. **F. Clean-up and revision** (spec gap, low): the clean-up still deletes older wraps when the state is unreadable; a garbage revision near 2^53 would overflow. *Taken:* the clean-up rewrites only a readable state; the parser caps `revision` below the largest safe integer.
