# Forgeability table

Every value a component of the library accepts from outside itself: who can produce it, what authenticates it, and what happens when it is missing or stale. Kept by the `adversarial` and `design` modes of [protocol-review](../skills/protocol-review/SKILL.md).

**Status:** seeded from the specs at `19de2d5` (after plan 010); checked against the code by reviews 006 (`3dc80a4`), 009 (`225392a`), 013 (`d889a7c`) 016 (`7ffd023`), 025 (`81b60c3`) and 037 (`093bd1e`), all `adversarial`; `team-state` rows marked retired after plan 026 (D-66). A row is a finding when someone in "Who can produce it" shouldn't, and "Authenticated by" doesn't stop them.

Actors: A1 data thief, A2 server, A3 network, A4 removed member, A5 member, A6 owner key, A7 device, A8 credential, A9 injected script, A10 outsider, A11 session. "Integration" means a value the integration hands the library.

## Vault (account context)

| Value | Who can produce it | Authenticated by | Missing or stale | § |
| --- | --- | --- | --- | --- |
| `account-key-wrap` | The account; A2 serves, withholds or replays archived ones; A11 replaces with garbage, **or with a PIN wrap that parses but whose `kdf` can't be used, or a device wrap that parses but doesn't open, both read as readable (037-B, C)** | AEAD under the method key, ids from the caller | `DEVICE_NOT_REGISTERED`, `PIN_NOT_SET_UP`; garbage: support restore (TH-36) | §4.1, §5.4 |
| Current account key version | A2 | Nothing; the device refuses one below the highest it saw | A new device adopts a retired one (TH-05, SP-19) ; a fresh device served the retired version after `secureAccount` recovers into it with the kept phrase (review 009 C) | §4.1 |
| `kdf` of the PIN wrap | A2 | AEAD associated data; bounds (§2) | Outside bounds: `MALFORMED_RECORD` | §2, §5.1 |
| OPRF evaluation and proof | The OPRF service; A2 (or a front end) can answer or refuse, but not prove without the key | The POPRF proof, checked against the public key the client's settings pin for the wrap's key id; the key id new wraps use is the settings' `writeKeyId` (D-53) | Refused: `PIN_RATE_LIMITED`; unpinned key id: `UNSUPPORTED_VERSION` before any work; bad proof: `TRUST_FAILURE` (`bad_signature`); a failed upgrade: reported (`pin-upgrade-failed`) | §5.1, §5.4, D-53 |
| `member-keys-wrap` | The account; A11 deletes, writes garbage, or **creates garbage under a new identity, which blocks every account-wide operation and has no archived generation to restore (review 016 B)**; A2 withholds | AEAD under the account key; the bundle checked against its published record | `NOT_GRANTED` or `not-joined`; deleted: support restore (TH-46) | §4.3 |
| Anchor floor (in the bundle) | The vault, from a chain it verified; whoever holds the account key (TH-20) | Inside the `member-keys-wrap` AEAD | The root of trust, with the vault's own anchor: a re-key or an export whose chain doesn't contain both fails and writes nothing; an owner's anchor repairs it; a vault that never verified the team trusts the floor it holds (TH-20, D-54); required in every bundle: one without a floor doesn't open, absent (D-66) | §4.3, §5.9, §6.1, D-54, D-66 |
| `member-keys` (public) | Its account; A11 under the account; A2 anything, for any account, and a different record per query (review 013 A); **any joiner: a malformed record that stops the team for everyone (review 016 C)** | Self-signature only; the held version's record must have the roster's `keysHash` in `reconcile` and `overview` (plan 014, after review 009 A); identity through a roster or an owner approval; proof by the held keys' recovery key | Withheld: `unverified` (D-46) | §4.2, §11 rule 8 |
| `team-state` (for the floor at re-key or rotation): **retired, D-66** | No longer accepted: the record, its `teamStateKey` and its compare-and-set are gone, and nothing the server stores is a root | — | Retired by plan 026 (review 039 A); its history is in D-52, D-62, D-63 | §4.4 (removed), D-66 |
| Recovery public key (`wrappedRecoveryPublicKey`) | The account; **whoever holds the account key, with the session, by a `replace` that keeps `wrappedAccountKey` (A9 in the vault, A7)** | AEAD under the account key, bound to account and version only, not to the wrap's `wrappedAccountKey` | Read only by operations given no phrase; given the phrase, the vault uses the typed key and reports a spliced one (`recovery-key-mismatch`); `secureAccount` rewrites it (D-56, after review 013 B) | §4.1, §5.11, D-56 |
| Owner's repair anchor (`rekey({ anchor })`, `secureAccount({ anchors })`) | An owner through the integration; **anyone who delivers it: A2 if relayed, a removed member posing as an owner; whoever holds the open vault, with no credential (037-D)** | Nothing; it replaces every root and the vault's anchor | A stale real one lowers the floor below a verified removal; a forged one roots a forged team (review 013 C) | §5.9, §6.8, D-54 |
| Invite anchor (`joinTeam`) | An owner through the integration; A2 when the server delivers the link | Nothing: it is checked against the served chain, not against its sender | Without one: the join is the first contact (TH-04) | §6.4 |
| Transfer request (`exportTeamKeys`) | The receiving context; anyone on the channel (A9; A2 if relayed) | Nothing; the integration decides who may ask (D-29) | Bad or low-order: `MALFORMED_RECORD`; a substituted one receives the member's private keys, the owner key included: accepted, the channel is the integration's (TH-39, review 013 E) | §3.8, TH-39 |
| Recovery phrase, PIN | The user; A8 | The wraps they open | `WRONG_CREDENTIAL` | §5.2, §5.6 |

## Team session (vault's context or a receiving one)

| Value | Who can produce it | Authenticated by | Missing or stale | § |
| --- | --- | --- | --- | --- |
| Bundles from the vault (same context) | The vault | In-process | — | §5.8 |
| Transfer (receiver's `openTeam`) | The vault; **anyone who saw the request** | `seal` context (account, team), one use; bundles checked against published records; **sender not authenticated** | Forged with A2: forged team (TH-49) | §3.8 |
| `team-key-version` chain | Owners; A6; A2 serves, withholds, forks; **an owner's session (A11) or any holder of the owner capability writes garbage at the next version, which stops the chain for good (025-C); any owner key: a valid version whose `wrappedPreviousKey` wraps the wrong key, which no reader checks (037-A)** | Owner signatures, the owner rule, hash links, anchors, published keys (§4.5) | `rollback`, `chain_conflict`; split view accepted (TH-38) | §4.5, §6.1 |
| `team-state`: **retired, D-66** | No longer accepted | — | Retired by plan 026 (review 039 A) | §4.4 (removed), D-66 |
| Local anchor (`LocalKeyStore`) | This device; A7, A9 on the device | Browser: AES-GCM under a non-extractable key (§3.7), which the page can still use | Absent: the server's and the floor; unreadable: an error. Never a source of the floor (D-51, review 005 A), and must link to the floor (D-52; review 006 B); any script in the origin can write any team's anchor, which stops that device only | §3.7, §6.1 |
| Roster entry for this member | An owner; A6 | Owner signature; its `keysHash` equals this member's keys | `pending` | §4.5, §6.1 step 5 |
| Approved keys (`KeysHandle`, at rotation) | The owner names `{ accountId, memberKeysVersion, keysHash }`; **A2 serves the record behind it, which may differ from the one reviewed** | The handle's keys hash, from the record whose proof or custody was checked (D-55, after review 013 A) | A newer version: `STALE_VERSION`; another record for the version, or two records for one version: `TRUST_FAILURE` (`key_mismatch`), nothing written | §6.5, §6.8, D-55 |
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
