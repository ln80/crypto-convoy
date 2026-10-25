# Review 033: design of plan 023 (D-56 amended, D-64, D-65)

Mode: `design`, with a fresh-context reviewer. Input: plan 023's spec, uncommitted, on top of `ef882e2`. Read only. The reviewer ran a throwaway probe against the code, then deleted it. All findings were taken into the spec before the spec commit.

1. **D-56 amended covered one variant only** (medium/high). A session can also drop the field, plant a record that doesn't parse, or garble `wrappedAccountKey`. *Taken:*
   - any recovery wrap that doesn't parse, or whose key can't be read, is a mismatch;
   - `warnings()` reports it and leaves out `rekey-needed`;
   - a setup with the PIN replaces the live wrap without parsing it;
   - a garbled `wrappedAccountKey` is accepted in TH-46: it reads as a wrong phrase, and the remedy is a setup with the PIN or a restore.
2. **D-65 overclaimed in SP-16** (medium). An owner who left can be named again, the server can roll back, and a session can delete wraps, and the integration's duty kept the old rule. *Taken:*
   - SP-16 narrowed, with a Limit;
   - D-65's Consequence;
   - the integration duty now says "a listed owner" and drops a departed account from the active list.
3. **D-64's "left out" read as a removal** (medium). *Taken:* the skipped account receives the new version with the keys it holds; a test will check it.
4. **`rekey-superseded` was API for nothing a person must do** (low/medium). *Taken:* dropped; the next run classifies the newer keys.
5. **A rotation with nothing left in it** (low). *Taken:* no rotation is written.
6. **Owners who can't step down** (low). *Taken:* §9, the using guide and D-65 say another owner removes them.
7. **Incomplete `MALFORMED_RECORD` refusals** (low). *Taken:*
   - `rotate` and `setOwners` refuse an owner left out of `keep`, or one who doesn't hold the version;
   - §9's row covers invalid arguments.
