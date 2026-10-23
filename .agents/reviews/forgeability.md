# Forgeability table

Every value a component of the library accepts from outside itself: who can produce it, what authenticates it, and what happens when it is missing or stale. Kept by the `adversarial` and `design` modes of [protocol-review](../skills/protocol-review/SKILL.md).

**Status:** seeded from the specs at `19de2d5` (after plan 010); checked against the code by review 006 (`adversarial`) at `3dc80a4`. A row is a finding when someone in "Who can produce it" shouldn't, and "Authenticated by" doesn't stop them.

Actors: A1 data thief, A2 server, A3 network, A4 removed member, A5 member, A6 owner key, A7 device, A8 credential, A9 injected script, A10 outsider, A11 session. "Integration" means a value the integration hands the library.

## Vault (account context)

| Value | Who can produce it | Authenticated by | Missing or stale | § |
| --- | --- | --- | --- | --- |
| `account-key-wrap` | The account; A2 serves, withholds or replays archived ones; A11 replaces with garbage | AEAD under the method key, ids from the caller | `DEVICE_NOT_REGISTERED`, `PIN_NOT_SET_UP`; garbage: support restore (TH-36) | §4.1, §5.4 |
| Current account key version | A2 | Nothing; the device refuses one below the highest it saw | A new device adopts a retired one (TH-05, SP-19) | §4.1 |
| `kdf` of the PIN wrap | A2 | AEAD associated data; bounds (§2) | Outside bounds: `MALFORMED_RECORD` | §2, §5.1 |
| OPRF evaluation, `currentKeyId` | A2 | Nothing: a wrong evaluation gives a wrong PIN key, so `WRONG_CREDENTIAL` | Refused: `PIN_RATE_LIMITED`; a moved key id forces an upgrade (budget) | §5.1, §5.4 |
| `member-keys-wrap` | The account; A11 deletes or writes garbage; A2 withholds | AEAD under the account key; the bundle checked against its published record | `NOT_GRANTED` or `not-joined`; deleted: support restore (TH-46) | §4.3 |
| Anchor floor (in the bundle) | The vault, from a chain it verified; whoever holds the account key (TH-20) | Inside the `member-keys-wrap` AEAD | The root of trust; no floor: `team-state` is a root too | §4.3, §6.1, D-52 |
| `member-keys` (public) | Its account; A11 under the account; A2 anything | Self-signature only; identity through a roster or an owner approval; proof by the held keys' recovery key | Withheld: `unverified` (D-46) | §4.2, §11 rule 8 |
| `team-state` (for the floor at re-key or rotation) | The account's sessions, in any context, from a verified chain (`advanceAnchor`); **any holder of a `teamStateKey` (the TH-20 attacker, any context that received a transfer)**; a session that opened a forged team (review 006 B); A11 garbage or delete; A2 older revisions | AEAD under a `teamStateKey`, revision bound; **the anchor isn't checked against a chain** | Unreadable: skipped (TH-46); older: the highest of it and the bundles' floors wins; forged: `state_conflict` or `rollback`, never the floor (D-52, after review 006 C) | §6.1, D-52 |
| Invite anchor (`joinTeam`) | An owner through the integration; A2 when the server delivers the link | Nothing: it is checked against the served chain, not against its sender | Without one: the join is the first contact (TH-04) | §6.4 |
| Transfer request (`exportTeamKeys`) | The receiving context; anyone on the channel (A9; A2 if relayed) | Nothing; the integration decides who may ask (D-29) | Bad or low-order: `MALFORMED_RECORD` | §3.8, TH-39 |
| Recovery phrase, PIN | The user; A8 | The wraps they open | `WRONG_CREDENTIAL` | §5.2, §5.6 |

## Team session (vault's context or a receiving one)

| Value | Who can produce it | Authenticated by | Missing or stale | § |
| --- | --- | --- | --- | --- |
| Bundles from the vault (same context) | The vault | In-process | — | §5.8 |
| Transfer (receiver's `openTeam`) | The vault; **anyone who saw the request** | `seal` context (account, team), one use; bundles checked against published records; **sender not authenticated** | Forged with A2: forged team (TH-49) | §3.8 |
| `team-key-version` chain | Owners; A6; A2 serves, withholds, forks | Owner signatures, the owner rule, hash links, anchors, published keys (§4.5) | `rollback`, `chain_conflict`; split view accepted (TH-38) | §4.5, §6.1 |
| `team-state` | The account's devices; A11 garbage or delete; A2 older revisions or withholding | AEAD under a `teamStateKey`, revision bound | Withheld or older: the floor bounds it (D-50); garbage: `state_unreadable` | §4.4, §6.1 |
| Local anchor (`LocalKeyStore`) | This device; A7, A9 on the device | Browser: AES-GCM under a non-extractable key (§3.7), which the page can still use | Absent: the server's and the floor; unreadable: an error. Never a source of the floor (D-51, review 005 A), and must link to the floor (D-52; review 006 B); any script in the origin can write any team's anchor, which stops that device only | §3.7, §6.1 |
| Roster entry for this member | An owner; A6 | Owner signature; its `keysHash` equals this member's keys | `pending` | §4.5, §6.1 step 5 |
| `activeAccountIds` (`reconcile`) | The integration; A2 server side | Nothing | A removed member listed as active stays in (TH-14) | §6.9 |
| `item` record (member) | A member; A2 swaps or moves; **any holder of an older team key version (A4, A5) with A2: a new or replacing record at that version** | AEAD under the team key of the version the record names, ids from the caller, manifest bound; write-once and "current version" only at the server (§11) | `DECRYPTION_FAILED`, `TRUST_FAILURE`; a record at an older version opens like any other (review 006 A) | §4.7, §7.2, §11 |
| Item parts, submission parts | The integration's storage; A2 | Size and hash in the manifest, then the stream | Missing or changed: `DECRYPTION_FAILED` | §4.8, §7.2 |
| `inbox` record | A member; A2 | AEAD under the team key; public key recomputed | `key_mismatch` | §4.9 |
| `submission` | Anyone with the inbox link (A10); A2 | Seal to the inbox key; the sender is anonymous (TH-31) | `DECRYPTION_FAILED` | §4.10 |
| `createdAt`, `createdBy` | The writer (A5) | Authenticated against the server only | Never used for a decision (TH-15, TH-35) | §1, §4.7 |

## Outside the team (links)

| Value | Who can produce it | Authenticated by | Missing or stale | § |
| --- | --- | --- | --- | --- |
| Item link key (fragment) | A member through the integration; A2 if the server sends the link | Nothing: the key is the capability (TH-23) | — | §7.3 |
| `item` record for a link holder | The integration's route; A2 | AEAD under the item key; `createdBy` and team version unchecked | `DECRYPTION_FAILED` | §7.3 |
| Inbox public key (fragment) | A member through the integration; A2 if the server sends the link | Nothing (TH-21) | Low-order: `MALFORMED_RECORD` | §7.5 |
