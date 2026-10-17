# Security properties

> Status: draft, under review. Verification paths name the tests to write; none exist yet.

## Role

Answers: **what security guarantees must always hold?**

[threat-model.md](threat-model.md) names the attacks. This document states what must stay true despite them, under which assumptions, and how each guarantee is checked. It is the reference for security tests and reviews: a property is useful only if a test can fail when it breaks.

Properties marked *deferred* depend on a decision that isn't in v1 ([decisions.md](decisions.md)); v1 doesn't claim them. A **Limit** line in an entry states what the property does *not* cover; it's part of the guarantee, not a footnote. Each property has a stable id `SP-01`, `SP-02`, and so on. Tests, vectors and pull requests cite those ids. How each property is achieved belongs in [key-hierarchy.md](key-hierarchy.md) and [protocol.md](protocol.md); this document only says *what*.

## Audience

Developers, testers, reviewers, auditors.

## How to read an entry

- **Property:** the guarantee, precise enough to be proven false.
- **Limits** (when present): what the guarantee doesn't cover.
- **Assumptions:** what it depends on. `AS-` ids refer to the [trust assumptions](threat-model.md#trust-assumptions).
- **Verification:** the tests that check it.
- **Related threats:** the `TH-` ids it answers.

## Index

| Id | Property |
| --- | --- |
| SP-01 | The server never holds a key that opens items |
| SP-02 | A team session only holds its own team's keys |
| SP-03 | Encrypted data can't be modified or moved undetected |
| SP-04 | Team keys go only to owner-approved member keys |
| SP-05 | Only a current owner can change the owner list |
| SP-06 | A removed member can't open items encrypted after a rotation |
| SP-07 | A client never goes back to an older team state |
| SP-08 | A PIN guess needs a server evaluation |
| SP-09 | A replaced PIN or recovery phrase stops working |
| SP-10 | A revoked device can't unlock the account again |
| SP-11 | The account key can be rotated |
| SP-12 | Compromised member keys can be replaced |
| SP-13 | An item's author is provable (deferred, D-09) |
| SP-14 | Only the team can open inbox submissions |
| SP-15 | Owner and membership changes are visible |
| SP-16 | Losing one owner never freezes a team with other owners |
| SP-17 | Unknown versions and algorithms are refused |
| SP-18 | Invalid input fails before crypto, and decryption never returns partial data |
| SP-19 | Recovering an account requires authorized material |
| SP-20 | Keys can be verified out of band (deferred, D-11) |
| SP-21 | A part reference reveals nothing without the item key |
| SP-22 | Automatic owner actions never widen access |
| SP-23 | A re-key proven by the recovery key is approved without an out-of-band check |
| SP-24 | An invite proof shows the joiner held the invite link |

---

## Confidentiality

### SP-01: The server never holds a key that opens items

Property: every record the library sends to the server is either public (public keys, signatures), or encrypted under a key the server never receives in clear. The server can't decrypt any item, team key, member key or account key from what it stores, sees or relays.

Limit: a link value isn't a record. A share link or inbox link that the integration's server sends itself, or that an email security service rewrites, gives that server or service the key it carries (TH-21, TH-23).

Assumptions: AS-01, AS-02.

Verification:
- `test/security/server-view.test.ts`: run every operation against a recording store, then check that no recorded byte sequence equals any key or plaintext used.

Related threats: TH-01, TH-29.

### SP-02: A team session only holds its own team's keys

Property: the account vault gives a team session only the keys of the team it asked for. A team session never receives the account key or another team's keys, and one team's keys can't decrypt another team's records. When the two run in separate contexts, a team's keys travel only sealed to the receiver created in the receiving context, bound to the account and the team: no other receiver opens them, they open only once, and a transfer for another account or team is refused.

Limit: which context may receive which team is the integration's decision (D-29). The vault exports to whoever the integration lets ask.

Assumptions: AS-01. The integration isolates the vault from team sessions ([Key custody](scope.md#key-custody)).

Verification:
- `test/security/team-isolation.test.ts`: open team A, then try to decrypt team B's records and to obtain the account key through the team session API.
- `test/security/key-transfer.test.ts`: open a transfer with another receiver, twice with the same receiver, for another team or account, and after tampering; check that the transfer contains no account key.
- `test/vectors/transfer.v1.json`.

Related threats: TH-19, TH-39.

### SP-06: A removed member can't open items encrypted after a rotation

Property: after a rotation that excludes a member, nothing that member holds (old team key versions, member keys, account key, and any key they copied while a member, AS-07) opens the new version, or items and inboxes created with it.

Limits:
- **Until a later grant.** If the member is granted a later version again, the chain (D-07) gives them every earlier version too, including those created while they were excluded.
- **Old inboxes.** Inboxes created before the rotation keep their key pair (TH-30, D-20).

Assumptions: AS-01. The rotation leaves the removed member out: rotations take an explicit list of accounts to keep, and `reconcile` keeps only active accounts (SP-22), so this is the default unless the integration lists the member (protocol §6.6). Writers use the new version (SP-07).

Verification:
- `test/security/member-removal.test.ts`: remove a member, rotate with the remaining members as the keep list, encrypt an item, then try every key the removed member held (refused). Re-admit them with a grant of a later version and check that the gap opens, as specified.

Related threats: TH-14.

### SP-14: Only the team can open inbox submissions

Property: a submission can be opened only with the inbox private key, which only holders of the inbox's team key version can reach. A sender can't open other submissions. A sender who got the inbox link outside the server seals to exactly the public key in the link.

Limit: holders of that version include members removed after the inbox was created. They can open later submissions to it if they obtain the ciphertexts (TH-30, D-20).

Assumptions: AS-01. For the last sentence: the link reaches the sender outside the server (TH-21).

Verification:
- `test/security/inbox.test.ts`: open a submission with a sender's material and with another team's keys; have the store offer a different inbox key and check the sender still seals to the raw public key from the link.

Related threats: TH-21, TH-22.

## Integrity and authenticity

### SP-03: Encrypted data can't be modified or moved undetected

Property: every ciphertext uses authenticated encryption bound to its context. Key records bind their team, item (or inbox and submission) and key version. Each part binds its index and is encrypted under its own item's (or submission's) random key; the key record lists every part's index, size and ciphertext hash (D-16, D-26). So a part can't be swapped, dropped, added, reordered or moved to another item without opening failing, and a key record moved to another id fails to open. Changing any byte makes decryption fail.

Assumptions: AS-01. Nonces are never reused under the same key.

Verification:
- `test/security/ciphertext-tampering.test.ts`: flip bits, truncate, and swap ciphertexts across parts, items, inboxes, teams and versions; drop, add and reorder parts.
- `test/vectors/item.v1.json`.

Related threats: TH-06, TH-29.

### SP-04: Team keys go only to owner-approved member keys

Property: a client seals a team key only to member keys that an owner approved for that member and team. A client opens a team key only from a version record's roster entry or a grant whose signer is in the owner list of that team key version, naming that member's own keys. Anything else is refused.

Assumptions: AS-01. The client trusts the right owner list (SP-05, SP-07; at first contact, trust on first use, TH-04).

Verification:
- `test/security/key-substitution.test.ts`: a malicious store swaps member keys, injects a fake member, replaces a sealed team key, and replays a grant meant for another member, team or version.

Related threats: TH-02.

### SP-05: Only a current owner can change the owner list

Property: each team key version carries the owner list for that version, and the versions form a hash chain (D-19). A client accepts version n only if it is signed by an owner of version n−1 and links to version n−1's record. It refuses gaps, and two different records for the same version. Once an owner is removed, their signatures are refused for every later version and for grants of every later version. Version numbers are consecutive, so no signer can choose them.

Assumptions: AS-01. The client starts from a trusted point (an anchor it verified, or trust on first use at first contact, TH-04).

Verification:
- `test/security/owner-chain.test.ts`: forged records; records signed by a non-owner or by a removed owner; gaps; forks (two records for one version); a removed owner signing a grant for a later version; and an owner change attempted as two separate writes (refused by construction).
- `test/vectors/team-key.v1.json`.

Related threats: TH-03, TH-17.

### SP-07: A client never goes back to an older team state

Property: a client keeps an anchor: the newest team key version record it verified (version and record hash), and the newest account key version it accepted. It refuses a chain that doesn't contain its anchor (shorter, or diverging) and an older account key version, and never encrypts with a team key version older than its anchor. It adopts a newer tip only after checking the chain from its anchor.

A `team-state` that fails to decrypt stops the client with `TRUST_FAILURE` (`state_unreadable`) instead of being ignored. An invite anchor received outside the server counts as an anchor for a new member.

Assumptions: the device's local storage keeps its state (`LocalKeyStore`), and the encrypted server copy can't be forged by the server (§4.4 of the protocol). A client with no anchor can't detect a rollback until it sees newer state (accepted in TH-05); that includes the account key version on a new device (SP-19).

Verification:
- `test/security/rollback.test.ts`: serve an older chain, a diverging chain, an older `team-state` revision, a corrupted `team-state`, a chain that doesn't contain the invite anchor, and an older team key version after a newer one was seen.

Related threats: TH-05.

### SP-13: An item's author is provable

Property: every item carries a signature by its author's member signing key. A reader accepts an item only if the signature is valid and the key belonged to a member approved by an owner at the item's team key version.

Assumptions: AS-01; SP-04 for knowing the approved keys.

Status: deferred (D-09). Not claimed by v1.

Verification:
- `test/security/authorship.test.ts`: a member signs an item claiming another author; a removed member signs a new item.

Related threats: TH-15.

## Credentials and recovery

### SP-08: A PIN guess needs a server evaluation

Property: nothing stored (backup, device storage) allows checking a PIN guess offline. Every guess requires one OPRF evaluation by the server for that account, and an evaluation made for one account doesn't help guess another account's PIN. Every evaluation counts as a guess, whatever its declared purpose. The PIN hashing cost is never below the library's hard floor (D-17).

Assumptions: AS-01, AS-05. Rate limiting, with one total budget per account, is enforced by the server ([server contract](scope.md#server-contract), rule 2).

Verification:
- `test/security/pin-hardening.test.ts`: try to open a backup with the correct PIN but no evaluation, with another account's evaluation, and with a wrong key.
- `test/vectors/pin-key.v1.json` (including the RFC 9497 vectors).

Related threats: TH-07, TH-08.

### SP-09: A replaced PIN or recovery phrase stops working

Property: after a PIN change or a recovery phrase replacement, the old PIN or phrase opens no record written after the change. The old credential stops working when the server deletes the old wrap, which it must do after a short delay ([server contract](scope.md#server-contract), rule 7). Until then, it still opens the current account key.

Assumptions: the server honours rule 7. A copy of an old wrap taken before the deletion still opens with the old credential; SP-11 covers that case.

Verification:
- `test/security/credential-rotation.test.ts`.

Related threats: TH-11.

### SP-10: A revoked device can't unlock the account again

Property: once a device is revoked, the server stops serving its wrap of the account key, and the device can't unlock the account again.

Limit: revocation doesn't evict someone who already copied keys from the device while it was unlocked (D-21). For that, `secureAccount` rotates the account key (SP-11) and re-keys every team with a recovery proof (SP-23).

Assumptions: AS-01. The server deletes the wrap ([server contract](scope.md#server-contract), rule 7). The device never caches its wrap, and the integration ends the device's sign-in sessions when revoking it. Revocation runs from another unlocked device or through recovery.

Verification:
- `test/security/device-revocation.test.ts`: revoke a device, then try to unlock with its device key (refused). Then run the full remedy and check that keys copied from the device open nothing written afterwards.
- `test/security/secure-account.test.ts`: a misused device; after `secureAccount` and an owner's `reconcile`, keys copied from it open nothing written afterwards; a team that failed to re-key is retried.

Related threats: TH-10.

### SP-11: The account key can be rotated

Property: an account can replace its account key without leaving any team and without changing its member keys. After rotation, the old account key opens no record the account writes afterwards. The PIN and the recovery phrase (or its replacement) open the new key; other devices must register again (D-10).

Limit: rotation retires the account key only. Member keys don't change, so anyone who already copied a member keys bundle (or the old account key and its wraps) keeps that team's access until the member re-keys in that team and the team key is rotated (SP-12); `secureAccount` does both (D-36). A rotation without the recovery phrase leaves the account without recovery until a new phrase is confirmed (D-35).

Assumptions: AS-01.

Verification:
- `test/security/account-rotation.test.ts`: rotate, then check that the old key opens no new account record and that every team still opens with the new key. Check that a copied bundle still opens the team until a re-key, as specified.

Related threats: TH-12, TH-20.

### SP-12: Compromised member keys can be replaced

Property: a member can get new member keys for a team. The new keys are accepted only once an owner approves them, by a rotation sealed to them; a signature by the old keys is never enough. An approval holds for exactly the keys the owner reviewed: keys published after the review, or replaced by a newer re-key, are refused. A rotation carries one set of keys per account, so after that rotation the old member keys open nothing new.

An optional continuity signature by the old keys is shown to the owner as a hint (routine re-key, or keys replaced without proof), never accepted as approval. A recovery signature is a proof (SP-23).

Assumptions: AS-01, AS-06 for the owner's check that the request is genuine.

Verification:
- `test/security/member-rekey.test.ts`: old keys sign their own replacement (refused as approval; reported as a routine re-key); an owner approves by rotating (accepted); the old keys get no grant of the new version and open nothing created after it; keys published after the owner's review, including an owner's own, are refused.
- `test/security/key-substitution.test.ts`: granting keys a re-key replaced is refused.

Related threats: TH-13.

### SP-19: Recovering an account requires authorized material

Property: the account key can be opened only with one of: the current PIN plus a server evaluation, the current recovery phrase, or a registered device whose wrap the server still holds. The server alone can't open it, and can't make a client accept an account key it forged (D-10).

Limit: on a device with no stored state, a malicious server that kept a **retired** account key version's wraps can make the device adopt that version: the user's own PIN or phrase still opens it. This matters only if someone also holds that old account key (TH-05).

Assumptions: AS-01, AS-05.

Verification:
- `test/security/recovery.test.ts`: each authorized path succeeds; revoked device, old phrase and server-only material fail.

Related threats: TH-11, TH-18.

## Owners and visibility

### SP-15: Owner and membership changes are visible

Property: every accepted change to the owner list and every newly approved member key is reported by the library to the integration, with the signer and what changed, on every member's client. Who received each version created by a rotation is its signed roster, which the server can't edit or trim. Owners also get an overview of each member's access, its proof, and what needs their action (members awaiting approval, unproven re-keys, a single owner). Reports come from the chain the library verifies, not from server notifications, so the server can't fake or skip one in the chain a client accepts. Each owner's key must match that account's published member keys, so a report names the account the key belongs to, unless the server also forges that account's member keys record.

Limit: this is detection, not prevention. Someone holding a stolen owner key can admit a member, rotate, and remove the other owners before anyone reads the report. Members admitted by a grant between two rotations are listed only as far as the server serves those grants (TH-42). The "granted by a removed owner" list shown during an owner removal is a warning, not a control: a later grant by another owner hides the origin (TH-17).

Assumptions: the integration displays these changes.

Verification:
- `test/security/change-visibility.test.ts`: each kind of change produces exactly one report, with the right signer; the owner overview follows each step; a hidden grant can't hide a roster member.

Related threats: TH-17.

### SP-16: Losing one owner never freezes a team with other owners

Property: in a team with two or more owners, any remaining owner can, without the others: approve members, rotate the team key, and add or remove owners, including the owner who lost their credentials.

Assumptions: at least one other owner can still unlock their account.

Verification:
- `test/security/owner-continuity.test.ts`: one owner disappears; another removes them, re-adds them with new keys, admits a member and rotates.

Related threats: TH-18.

### SP-20: Keys can be verified out of band

Status: deferred (D-11). Not claimed by v1.

Property: the library gives a short, stable fingerprint of each member's keys. A user can mark keys as verified after comparing fingerprints. Verified keys that later change are reported, never replaced silently.

Assumptions: fingerprints are compared through a channel the server doesn't control.

Verification:
- `test/security/fingerprints.test.ts`: fingerprint stability (vectors), change of a verified key raises a report.
- `test/vectors/fingerprints.v1.json`.

Related threats: TH-04.

## Robustness

### SP-17: Unknown versions and algorithms are refused

Property: every record declares its format version and algorithms, and every value carried in a link starts with a format version prefix. A client checks them against a fixed list of supported values before any cryptographic operation, and refuses anything else. There is no fallback to an older or weaker path.

Assumptions: none.

Verification:
- `test/security/downgrade.test.ts`: unknown, older and mismatched versions and algorithms, on every record type and on link values (unknown prefix).

Related threats: TH-24.

### SP-18: Invalid input fails before crypto, and decryption never returns partial data

Property: every record is checked (types, lengths, bounds, encodings, trailing data) before any cryptographic operation. The default decryption API is buffered: it either returns the full plaintext or fails with a typed error, never partial, empty or unauthenticated data, and it refuses parts larger than the integration's `maxBufferedSize` before downloading them. The streaming API is opt-in: it delivers only authenticated chunks, and an incomplete stream ends with an error so the consumer can discard what it received.

Assumptions: none.

Verification:
- `test/fuzz/records.fuzz.test.ts`: generated malformed records for every parser.
- `test/security/partial-decrypt.test.ts`: truncated streams, missing final chunks, and a part above `maxBufferedSize` (refused before download).

Related threats: TH-25.

### SP-21: A part reference reveals nothing without the item key

Property: a reference made with `partRef` is a keyed hash under a key derived from the item's (or submission's) content key (§3.9). Without that key, nobody can compute the reference of a candidate content, and references of the same content in two items differ.

Limit: within one item, equal contents give equal references: that is what deduplication needs, and the server sees it. Anyone holding the item key (members, link holders) can compute references for that item.

Assumptions: AS-01.

Verification:
- `test/security/part-ref.test.ts`: same content in two items gives different references; a reference doesn't match any unkeyed hash of the content; equal content within an item gives the same reference.
- `test/vectors/part-ref.v1.json`.

Related threats: TH-40.

## Owner autopilot and proofs

### SP-22: Automatic owner actions never widen access

Property: `reconcile` (D-31) gives a team key version only to accounts that already hold the current version with the same keys, to accounts whose re-key is proven by their recovery key (SP-23) and who aren't owners, and, only when the integration enables `autoApproveInvites`, to first-time joiners with a valid invite proof (SP-24). It never gives a version to an account granted only an older version, to unproven keys, or to an owner's new keys. It never changes the owner list. Removing an account from the active list leads to a rotation without it.

Limit: the active list comes from the integration. An account the integration wrongly lists as active, and that still holds the current version, keeps it; one wrongly left out loses access until an owner approves it again.

Assumptions: AS-01. An owner runs `reconcile` with the integration's active list.

Verification:
- `test/security/reconcile.test.ts`: a removed member listed as active again is not re-granted; an inactive holder is rotated out; unproven re-keys, owners' re-keys and joins without an accepted proof are returned as needing a human; a dry run writes nothing.
- `test/properties/reconcile.properties.test.ts`: for any snapshot, the plan gives the new version to no account outside the rule above.

Related threats: TH-14, TH-37.

### SP-23: A re-key proven by the recovery key is approved without an out-of-band check

Property: a `member-keys` record signed by the recovery key that the account's currently held keys carry is a proven re-key. Owners' clients approve it in `reconcile` for accounts that aren't owners of the current version; a continuity signature or no signature never counts. Neither a stolen device nor a stolen session can produce the proof: the recovery signing key is derived from the phrase when the user types it and never stored. Replacing the phrase re-keys every team with the new recovery key, proven by the old phrase if given.

Limits:
- **A leaked phrase** proves re-keys too: a thief can replace a member's keys in every team, racing the real user (TH-41).
- **Owners** are never approved automatically, even with a proof.
- A phrase replaced **without** the old one re-keys every team without proof, so each needs a human approval.

Assumptions: AS-01, AS-03 for the device where the phrase is typed.

Verification:
- `test/security/recovery-proof.test.ts`: a session thief's re-key (no phrase) stays a hint; a recovery-signed re-key is approved; one signed with another phrase is not; an owner's proven re-key needs a human; a leaked phrase's re-key is reported; a phrase replaced with and without the old one.
- `test/vectors/recovery-key.v1.json`.

Related threats: TH-10, TH-12, TH-13, TH-37, TH-41.

### SP-24: An invite proof shows the joiner held the invite link

Property: an invite proof in a `member-keys` record verifies only with the join secret of an `invite` record that an owner of that version signed, over exactly those keys and that account. Owners see it as a hint; `reconcile` admits the joiner automatically only when the integration enables `autoApproveInvites`, only for an invite of the current team key version, and only once per invite.

Limit: it proves possession of the link, not identity. Whoever saw the link (the integration's server and mail provider if they delivered it, anyone reading a stored outbox or logs) can make a valid proof (TH-43).

Assumptions: AS-01. The integration keeps invite links out of its own UI and logs.

Verification:
- `test/security/invite-proof.test.ts`: a valid proof; a wrong secret, another account, other keys; an invite of an older version; a second join with one invite; `autoApproveInvites` off and on.
- `test/vectors/invite.v1.json`.

Related threats: TH-02, TH-04, TH-37, TH-43.

