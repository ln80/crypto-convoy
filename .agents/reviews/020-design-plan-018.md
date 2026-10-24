# Review 020: design of plan 018 (D-59, D-60, D-61)

Mode: `design`, with a fresh-context reviewer. Input: plan 018's first design, at `490737e`. Read only. Each finding was checked against the code it cites; all were taken, and the design was rewritten (plan 018).

## Findings

1. **D-59 helps only devices with a vault anchor** (forgeable input, medium). Elsewhere the server withholds the wraps and a join is a first contact; a stateless guard fails, since the server withholds the published records too. *Taken:* one rule for every vault verification instead of a join-specific one; the stateless case documented in TH-04 with a Duty (re-join only with an owner's anchor).
2. **D-59 can leave the user stuck** (spec gap, medium): a vault anchor already moved to a forged tip refuses the real invite anchor, and `rekey` throws `NOT_GRANTED` with no bundle (`recovery.ts:106-108`). Letting the invite anchor replace it would let a server roll the vault back. *Taken:* `rekey` with an owner's anchor runs with no bundle.
3. **`teamIds` is the server's** (forgeable input, low): it can only add reports, and a team it omits is today's behaviour; a spurious entry is repaired only with an owner's anchor. *Taken:* stated, with id validation.
4. **Warnings still list teams from wraps** (missing path, low): a deleted wrap with bait keys hides `foreign-member-keys` for that team. *Accepted* in D-60 (`secureAccount` with `teamIds` reports it).
5. **Re-joining is unproven** (hardening, medium): `joinTeam` never signs, so owners approve by hand while the stolen keys stay rostered. *Taken:* the repair is a proven `rekey` with an owner's anchor and no bundle.
6. **D-61's condition is forgeable** (forgeable input, high): "the account holds team wraps" is deletable by a session and withheld by the server, so the credential-free setup stayed open. *Taken:* every recovery setup needs a current credential; the first-setup exception is deleted.
7. **D-61's premise was partly wrong** (wrong claim, low): a user who kept the old phrase proves the re-keys with `oldPhrase`; `recover` gives `STORE_ERROR` with no recovery wrap. *Taken:* both stated; `recover` answers `RECOVERY_NOT_SET_UP`.
8. **Budget check:** D-59 and D-60 add no state; D-61 as first written chose whether to ask for a credential from a server-controlled value. After the rewrite, D-59 and D-61 are free (one rule merged, one exception deleted, one refusal lifted) and D-60 small.
