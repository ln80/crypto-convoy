# Security properties

> Status: draft, under review. Verification paths name the tests; the traceability test (`test/unit/traceability.test.ts`) checks that each non-deferred property's tests exist and cite it.

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
| SP-24 | An invite proof shows the joiner held the invite link (deferred, D-32) |
| SP-25 | An open vault alone can't change the account's credentials |
| SP-26 | A session can't destroy an account's private records |

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

Limit: which context may receive which team is the integration's decision (D-29). The vault exports to whoever the integration lets ask. A receiver doesn't know who sealed a transfer: one sealed by whoever saw the request opens too, with keys of their own (TH-49).

Assumptions: AS-01. The integration isolates the vault from team sessions ([Key custody](scope.md#key-custody)).

Verification:
- `test/security/team-isolation.test.ts`: open team A, then try to decrypt team B's records and to obtain the account key through the team session API.
- `test/security/key-transfer.test.ts`: open a transfer with another receiver, twice with the same receiver, for another team or account, and after tampering; check that the transfer contains no account key.
- `test/vectors/transfer.v1.json`.
- `formal/transfer.spthy`: lemmas `keys_secret_on_authentic_channel`, `accepts_only_exports_on_authentic_channel`, `transfer_opens_only_for_its_account_and_team`, `receiver_opens_once`, `floor_arrives_intact`; and the accepted attacks `attack_TH39_substituted_request`, `attack_TH49_forged_transfer` (Tamarin, `npm run check:formal`, plan 027).

Related threats: TH-19, TH-39, TH-49.

### SP-06: A removed member can't open items encrypted after a rotation

Property: after a rotation that excludes a member, nothing that member holds (old team key versions, member keys, account key, and any key they copied while a member, AS-07) opens the new version, or items and inboxes created with it.

Limits:
- **Until a later rotation lists them.** If the member receives a later version again, the chain (D-07) gives them every earlier version too, including those created while they were excluded.
- **Old inboxes.** Inboxes created before the rotation keep their key pair (TH-30, D-20).

Assumptions: AS-01. The rotation leaves the removed member out: rotations take an explicit list of accounts to keep, and `reconcile` keeps only active accounts (SP-22), so this is the default unless the integration lists the member (protocol §6.6). Writers use the new version (SP-07).

Verification:
- `test/security/member-removal.test.ts`: remove a member, rotate with the remaining members as the keep list, encrypt an item, then try every key the removed member held (refused). Re-admit them in a later rotation and check that the gap opens, as specified.
- `formal/chain.spthy`: lemma `team_key_reaches_only_rostered_accounts`, for chains of three versions (flag DEPTH3; Tamarin, `npm run check:formal`, plan 027).

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

Limit: this holds against the server alone. Anyone who holds a team key version, including a member removed since, can build a new key record for any item id at that version, and with the server's help it opens for every member like the real one: only the server's write-once and current-version rules keep it out (TH-50, §11).

Assumptions: AS-01. Nonces are never reused under the same key.

Verification:
- `test/security/ciphertext-tampering.test.ts`: flip bits, truncate, and swap ciphertexts across parts, items, inboxes, teams and versions; drop, add and reorder parts. Limit: a removed member's record at a version he held opens, served in place of an item or as a new one.
- `test/vectors/item.v1.json`.

Related threats: TH-06, TH-29, TH-50.

### SP-04: Team keys go only to owner-approved member keys

Property: a client seals a team key only to member keys that an owner approved for that member and team. A client opens a team key only from its own entry in the roster of a version record signed by an owner of the previous version, naming that member's own keys (D-37). Anything else is refused.

Assumptions: AS-01. The client trusts the right owner list (SP-05, SP-07; at first contact, trust on first use, TH-04).

Verification:
- `test/security/key-substitution.test.ts`: a malicious store swaps member keys, injects a fake member or a forged version, replaces a sealed team key, and moves a roster entry to another member or team.
- `formal/chain.spthy`: lemmas `team_key_reaches_only_rostered_accounts` (flag DEPTH3), `owner_rule` (Tamarin, `npm run check:formal`, plan 027).

Related threats: TH-02.

### SP-05: Only a current owner can change the owner list

Property: each team key version carries the owner list for that version, and the versions form a hash chain (D-19). A client accepts version n only if it is signed by an owner of version n−1 and links to version n−1's record. It refuses gaps, and two different records for the same version. Once an owner is removed, their signatures are refused for every later version. Version numbers are consecutive, so no signer can choose them.

Assumptions: AS-01. The client starts from a trusted point (an anchor it verified, or trust on first use at first contact, TH-04).

Verification:
- `test/security/owner-chain.test.ts`: forged records; records signed by a non-owner or by a removed owner; gaps; forks (two records for one version); and a version whose owner doesn't hold it (missing from its roster).
- `test/vectors/team-key.v1.json`.
- `formal/chain.spthy`: lemmas `owner_rule`, `no_fork_without_owner_key`, `link_wraps_the_held_key`; and the accepted attacks `attack_TH38_split_view`, `attack_037A_wrong_previous_key` (Tamarin, `npm run check:formal`, plan 027).

Related threats: TH-03, TH-17.

### SP-07: A client never goes back to an older team state

Property: a client keeps an anchor: the newest team key version record it verified (version and record hash), and the newest account key version it accepted. It refuses a chain that doesn't contain its anchor (shorter, or diverging) and an older account key version, and never encrypts with a team key version older than its anchor. It adopts a newer tip only after checking the chain from its anchor.

Its member keys carry an anchor floor, required in every bundle (D-66), the account's root of trust: version 1 for the team's creator, the chain verified at join for a joiner, from the invite anchor if one was given; the vault moves it only along a chain that contains every root it holds for the team, the floor and its own anchor, when it opens or exports the team and at a re-key, or from an anchor an owner gives; roots that conflict fail the re-key, never carry a floor (D-48, D-52, D-54). The client fetches the chain from the lowest of the floor and its local anchor, and the chain must contain both: a local anchor written by someone else can't choose the chain; in the vault's context and in a receiving context alike (§3.8). Nothing the server stores is a root (D-66).

Assumptions: the device's local storage keeps its state (`LocalKeyStore`). A member who joined without an invite anchor, or whose invite link the server delivered, trusted the chain served at join (TH-04). A client that starts from its floor can't detect a rollback to a version between the floor and newer state until it sees that state (accepted in TH-05), and the server can serve an older wrap with an older floor; that includes the account key version on a new device (SP-19). Whoever holds the account key can write a floor: a vault holding its own anchor for the team refuses one written directly (the re-key fails), not one given through the open vault with an anchor, which needs no credential, nor one planted by a script that also deletes the vault's anchor; an anchor from an owner repairs the device that runs the repair, also one with no anchor, while a server can still serve a new device of the account the planted wrap (TH-20, D-54). That anchor replaces every root, this device's local anchor included, and is trusted as given: one that didn't come from an owner outside the server can root the account on a forged chain, or below a verified version (TH-04).

Verification:
- `test/security/rollback.test.ts`: serve an older chain, a diverging chain, a chain that doesn't contain the invite anchor (refused at join, also when the account already has keys), a forged chain to a new device (refused from the floor, in the vault's context and through a receiver, for a joiner without an invite anchor too), a local anchor above the floor naming a forged version (refused), and an older team key version after a newer one was seen; Limit: a forged chain served at a join without an invite anchor is trusted. A bundle in the layout without a floor, planted with the account key, doesn't open and is absent, and a transfer entry without a floor is refused (D-66).
- `test/security/account-rotation.test.ts`: the floor moves along a chain containing every root when the vault opens or exports the team and at a re-key, and is kept by an account rotation; a re-key whose roots conflict or whose chain fails writes nothing; a local anchor doesn't reach it; a floor planted with the account key fails `secureAccount` in either layout, export refuses it, and an owner's anchor repairs it. An existing member's join without an anchor refuses a forged chain when the server withholds its wraps, and an owner's anchor re-keys a team with no bundle (D-59). A join that finds keys checks the floor they carry (review 021 D). The repair with an owner's anchor makes a device whose local anchor came from a forged first contact open the real chain (review 035 A).
- `formal/chain.spthy`: lemmas `anchored_join_holds_the_real_version`; and the accepted attack `attack_TH04_first_contact` (Tamarin, `npm run check:formal`, plan 027).

Related threats: TH-04, TH-05.

### SP-13: An item's author is provable

Property: every item carries a signature by its author's member signing key. A reader accepts an item only if the signature is valid and the key belonged to a member approved by an owner at the item's team key version.

Assumptions: AS-01; SP-04 for knowing the approved keys.

Status: deferred (D-09). Not claimed by v1.

Verification:
- `test/security/authorship.test.ts`: a member signs an item claiming another author; a removed member signs a new item.

Related threats: TH-15.

## Credentials and recovery

### SP-08: A PIN guess needs a server evaluation

Property: nothing stored (backup, device storage) allows checking a PIN guess offline. Every guess requires one OPRF evaluation by the server for that account, and an evaluation made for one account doesn't help guess another account's PIN. Every evaluation counts as a guess, whatever its declared purpose. Every evaluation carries a proof, checked against the public key the client's settings pin for the key id, and the key id new wraps use is a setting too: a server that answers without the real key, or picks the key id, is refused (`TRUST_FAILURE`, `UNSUPPORTED_VERSION`) instead of making a wrap that can be checked offline (D-53). The PIN hashing cost is never below the library's hard floor (D-17).

Assumptions: AS-01, AS-05. Rate limiting, with one total budget per account, is enforced by the server ([server contract](scope.md#server-contract), rule 2).

Verification:
- `test/security/pin-hardening.test.ts`: try to open a backup with the correct PIN but no evaluation, with another account's evaluation, and with a wrong key; answer an evaluation with another key, a forged or replayed proof, or an unpinned key id (refused before any wrap is written); check that the server never chooses the key id, and that an unlock stands when only its upgrade fails, reported once and not retried at each unlock.
- `test/vectors/pin-key.v1.json` (including the RFC 9497 POPRF vectors).

Related threats: TH-07, TH-08, TH-34, TH-51.

### SP-09: A replaced PIN or recovery phrase stops working

Property: after a PIN change or a recovery phrase replacement, the old PIN or phrase opens no record written after the change. The old credential stops working as soon as the new wrap is stored: the replacement takes the old wrap's place, which the server archives without serving it ([server contract](scope.md#server-contract), rule 7; D-39).

Assumptions: the server honours rule 7. A copy of an old wrap taken before the replacement, or served again by the server from its archive, still opens with the old credential; SP-11 covers that case. That is also what lets support restore an account after TH-36.

Verification:
- `test/security/credential-rotation.test.ts`: the old PIN and phrase fail right after a change; a garbage replacement is undone by restoring the archived wrap (TH-36).

Related threats: TH-11, TH-20, TH-36.

### SP-10: A revoked device can't unlock the account again

Property: once a device is revoked, the server stops serving its wrap of the account key, and the device can't unlock the account again.

Limits:
- Revocation doesn't evict someone who already copied keys from the device while it was unlocked (D-21). For that, `secureAccount` rotates the account key (SP-11) and re-keys every team with a recovery proof (SP-23).
- The server may keep serving a revoked wrap for a short delay, and keeps it archived for the restore window, from which the integration's support process can restore it ([server contract](scope.md#server-contract), rule 7; D-39).

Assumptions: AS-01. The server stops serving the wrap ([server contract](scope.md#server-contract), rule 7). The device never caches its wrap, and the integration ends the device's sign-in sessions when revoking it. Revocation runs from another unlocked device or through recovery.

Verification:
- `test/security/device-revocation.test.ts`: revoke a device, then try to unlock with its device key (refused). Then run the full remedy and check that keys copied from the device open nothing written afterwards.
- `test/security/secure-account.test.ts`: a misused device; after `secureAccount` and an owner's `reconcile`, keys copied from it open nothing written afterwards; a team that failed to re-key is retried. With the PIN budget spent, `secureAccount` with the phrase alone cuts the thief's PIN and devices, and a PIN is set later (D-40, TH-44). In a single-owner team, the owner's own `reconcile` approves its re-key, and the copied owner key can't sign a later version (D-47). A team whose wrap a thief deleted is reported failed when the product lists it, and a proven re-key with an owner's anchor ends the stolen keys (D-60).

Related threats: TH-10.

### SP-11: The account key can be rotated

Property: an account can replace its account key without leaving any team and without changing its member keys. After rotation, the old account key opens no record the account writes afterwards. The recovery phrase entered at rotation, which it keeps, and the new PIN, if one is given, open the new key (D-41). `secureAccount` given a new phrase stores that one instead, and the replaced phrase opens nothing of the new version (D-45). Other devices must register again (D-10).

Limit: rotation retires the account key only. Member keys don't change, so anyone who already copied a member keys bundle (or the old account key and its wraps) keeps that team's access until the member re-keys in that team and the team key is rotated (SP-12); `secureAccount` does both (D-36). A rotation without a new PIN leaves the account without a PIN until one is set (D-40). The retired version stays usable to whoever reaches it: a server that serves it to a stateless or stale device, or a support restore, brings it back, and the user's unchanged PIN or phrase opens it, with keys the attacker holds (SP-19); a new phrase and a different PIN shrink that, and the integration resets the account's other devices after `secureAccount`.

Assumptions: AS-01.

Verification:
- `test/security/account-rotation.test.ts`: rotate, then check that the old key opens no new account record and that every team still opens with the new key. Check that a copied bundle still opens the team until a re-key, as specified. A `secureAccount` PIN that opens the current PIN wrap is refused, also when the server splits the budget by purpose: the check draws on the share the new PIN does (§5.11).
- `test/security/secure-account.test.ts`: securing with a new phrase: the old phrase opens nothing, the new one unlocks, every team's re-key is proven and approved by `reconcile`; a new phrase that isn't the one shown is refused before anything is written.

Related threats: TH-10, TH-11, TH-12, TH-20, TH-44, TH-48.

### SP-12: Compromised member keys can be replaced

Property: a member can get new member keys for a team. The new keys are accepted only once an owner approves them, by a rotation sealed to them; a signature by the old keys is never enough. An approval holds for exactly the keys the owner reviewed, named by version and keys hash (D-55): keys published after the review, or replaced by a newer re-key, are refused (`STALE_VERSION`), and another record served for the reviewed version is `TRUST_FAILURE` (`key_mismatch`), as are two records for one version. A rotation carries one set of keys per account, so after that rotation the old member keys open nothing new. Keys published under the account by someone else never block the member's own writes: new keys take the newest published version plus one, and the vault reports keys it didn't make, for the teams where it holds keys (`foreign-member-keys`, D-43).

A recovery signature is the only proof (SP-23, D-38); any other re-key is shown to the owner as unproven, for an out-of-band check.

Limit: keys published, or a team created, under the account in a team where the vault holds no keys aren't reported (TH-37). Limit: only the newest published keys can be approved. While someone else keeps publishing under the account (a session thief, TH-47), keys they publish after the member's leave the member's keys unapprovable, proven or not, until the integration ends the account's other sessions.

Assumptions: AS-01, AS-06 for the owner's check that the request is genuine.

Verification:
- `test/security/member-rekey.test.ts`: keys published without proof are reported as unproven and never approved by themselves; an owner approves by rotating (accepted); the old keys get no roster entry of the new version and open nothing created after it; keys published after the owner's review, including an owner's own, are refused; once the new keys are approved the vault deletes the old bundle, and the team still opens. A session thief publishes keys at the member's next version: the member's join and re-key still succeed, at the following version, and the vault reports the foreign keys until they're superseded. Limit: bait published after each proven re-key keeps it from being approved.
- `test/security/key-substitution.test.ts`: approving keys a re-key replaced is refused; a server serving another record for the reviewed version at rotation, or two records for one version, is refused before anything is written, for a member's proven re-key, an owner's own re-key and a manual approval (D-55).
- `test/security/secure-account.test.ts`: keys published by a session thief before `secureAccount` don't block its re-keys or their approval by `reconcile`.

Related threats: TH-12, TH-13, TH-20, TH-37, TH-47.

### SP-19: Recovering an account requires authorized material

Property: the account key can be opened only with one of: the current PIN plus a server evaluation, the current recovery phrase, or a registered device whose wrap the server still holds. The server alone can't open it, and can't make a client accept an account key it forged (D-10).

Limit: on a device with no stored state, a malicious server that kept a **retired** account key version's wraps can make the device adopt that version: the user's own PIN or phrase still opens it. It matters exactly when someone holds that old account key, which is the case `secureAccount` answers: keys made there are the attacker's. A device that last saw the retired version adopts it the same way, and a support restore returns to it with an honest server (TH-05, TH-48).

Assumptions: AS-01, AS-05.

Verification:
- `test/security/recovery.test.ts`: each authorized path succeeds; revoked device, old phrase and server-only material fail.

Related threats: TH-11, TH-18.

## Owners and visibility

### SP-15: Owner and membership changes are visible

Property: every change to the owner list or to the roster (accounts added, removed or re-keyed) in the records a client verifies since its last verified state is reported by the library to the integration, with the signer and what changed, on every member's client: each device or context reports every record above its lowest root, so what one device saw doesn't hide it from another (D-44, D-57). Who received each version created by a rotation is its signed roster, which the server can't edit or trim. Owners also get an overview of each member's access, its proof, and what needs their action (members awaiting approval, unproven re-keys, a single owner). Reports come from the chain the library verifies, not from server notifications, so the server can't fake or skip one in the chain a client accepts. Every roster entry and every owner's key must match that account's published member keys (D-46), so a report names the account the keys belong to, unless the server also forges that account's member keys record.

Limit: this is detection, not prevention. Someone holding a stolen owner key can admit a member, rotate, and remove the other owners before anyone reads the report. The "given by a removed owner" list shown during an owner removal is a warning, not a control: a later rotation by another owner hides the origin (TH-17).

Assumptions: the integration displays these changes, in every context that opens a team; a context with no stored anchor of its own (a fresh device, a receiver whose anchor store doesn't persist) reports nothing older than the account's floor.

Verification:
- `test/security/change-visibility.test.ts`: each kind of change produces exactly one report, with the right signer; the owner overview follows each step; every member sees every admission in the roster; a member admitted and removed again between two opens is reported to a member whose anchor predates both; a rotation that seals to keys an existing member never published, to pass an admission off as a re-key, is refused (`key_mismatch`). A second device reports a change another device already showed; a split layout reports from its second open; a reload keeps the reports a session held (D-57).

Related threats: TH-17, TH-41.

### SP-16: Losing one owner never freezes a team with other owners

Property: in a team with two or more owners, any remaining owner can, without the others: approve members, rotate the team key, and add or remove owners, including the owner who lost their credentials. `leaveTeam` refuses a listed owner, who steps down first (D-65).

Limit: a team can still end with listed owners who hold no keys: an account that left and is named owner again by another owner, a server serving a chain from before the account became owner, and a session deleting an owner's wraps (TH-46) (D-65).

Assumptions: at least one other owner can still unlock their account.

Verification:
- `test/security/owner-continuity.test.ts`: one owner disappears; another removes them, re-adds them with new keys, admits a member and rotates. A listed owner's leave is `LAST_OWNER`; after stepping down it leaves; two owners can't both leave; a member who isn't an owner leaves (D-65). A rotation may name as owner an account whose keys it approves (§6.7).

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

Property: every record is checked (types, lengths, bounds, encodings, trailing data) before any cryptographic operation. In a list, a record that fails its checks is left out and never stops the others: a `member-keys` record of the team, a member keys wrap or a device wrap of the account (D-58). The default decryption API is buffered: it either returns the full plaintext or fails with a typed error, never partial, empty or unauthenticated data, and it refuses parts larger than the integration's `maxBufferedSize` before downloading them. The streaming API is opt-in: it delivers only authenticated chunks, and an incomplete stream ends with an error so the consumer can discard what it received.

Limit: a chain can't leave a version out, so a team key version that fails its checks, which an owner's session can publish at the next version, stops the team for every member (TH-25).

Assumptions: none.

Verification:
- `test/fuzz/records.fuzz.test.ts`: generated malformed records for every parser.
- `test/security/partial-decrypt.test.ts`: truncated streams, missing final chunks, and a part above `maxBufferedSize` (refused before download).
- `test/security/key-substitution.test.ts`: a joiner's `member-keys` record with a bad signature is left out; every member and owner still works (D-58). Limit: an owner's session publishes a team key version with a bad signature, and every member is `unverified` (`bad_signature`).

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

Property: `reconcile` (D-31) gives a team key version only to accounts that already hold the current version with the same keys, to accounts whose re-key is proven by their recovery key (SP-23) and who aren't owners, and to the calling owner's own new keys when its session holds them (D-47). It never gives a version to a first-time joiner, to an account that held only an older version, to unproven keys, or to another owner's new keys. It never adds or removes an owner, and replaces only the caller's own owner key: an inactive owner is left to a human. Removing any other account from the active list leads to a rotation without it. Keys an account publishes while `reconcile` runs never stop its removals: that approval is left out and reported (D-64).

Limits:
- The active list comes from the integration. An account the integration wrongly lists as active, and that still holds the current version, keeps it; one wrongly left out loses access until an owner approves it again.
- The caller's own re-key is approved for keys its vault holds, which proves custody, not authorship: whoever holds the account key (TH-12) can wrap a bundle the vault then holds. They already hold the caller's owner key, so nothing widens beyond what they could sign (D-47).

Assumptions: AS-01. An owner runs `reconcile` with the integration's active list.

Verification:
- `test/security/reconcile.test.ts`: a removed member listed as active again doesn't get the version back; an inactive holder is rotated out; unproven re-keys, other owners' re-keys, inactive owners and joins are returned as needing a human; the caller's own re-key is approved when its session holds the keys, never when they were published by someone else (D-47); a dry run writes nothing. A member publishing newer proven keys during `reconcile` keeps the version with the keys it holds, and the inactive holder is still removed (D-64).
- `test/properties/reconcile.properties.test.ts`: for any snapshot, the plan gives the new version to no account outside the rule above.

Related threats: TH-14, TH-37.

### SP-23: A re-key proven by the recovery key is approved without an out-of-band check

Property: a `member-keys` record signed by the recovery key that the account's currently held keys carry is a proven re-key. The held keys are those the roster pins by keys hash: a record the server serves for that version with another hash is `TRUST_FAILURE` (`key_mismatch`), so the server can't choose the recovery key a proof is checked against. Owners' clients approve it in `reconcile` for accounts that aren't owners of the current version; anything else never counts as a proof. An owner's own re-key is approved by its own `reconcile` through possession of the keys instead (SP-22, D-47). Neither a stolen device nor a stolen session can produce the proof: the recovery signing key is derived from the phrase when the user types it and never stored. The vault signs only keys carrying the recovery key of a phrase typed in that operation, the current one or the new one being set, never a key read from the server, which an account-key holder can rewrite (D-56). Replacing the phrase re-keys every team with the new recovery key, proven by the old phrase if given.

Limits:
- **A leaked phrase** proves re-keys too: a thief can replace a member's keys in every team, racing the real user (TH-41).
- **Owners** are never approved automatically by a proof, even a valid one; only the owner's own `reconcile`, holding the keys, approves them (D-47).
- A phrase replaced with the PIN instead of the old phrase (D-41) re-keys every team without proof, so each needs a human approval.
- Keys made without the phrase (`createTeam`, `joinTeam`, `rekey` without one) carry the recovery wrap's stored key: if an account-key holder rewrote it, its re-keys are proven in those teams until an owner approves the user's re-key by hand (TH-12, D-56).

Assumptions: AS-01, AS-03 for the device where the phrase is typed.

Verification:
- `test/security/recovery-proof.test.ts`: a session thief's re-key (no phrase) stays a hint; a recovery-signed re-key is approved; one signed with another phrase is not; an owner's proven re-key needs a human; a leaked phrase's re-key is reported; a phrase replaced with and without the old one; a failed team retried with the new phrase and the old one is proven, and an old phrase no bundle carries is refused (D-49, D-56); a recovery wrap whose public key an account-key holder replaced: `secureAccount` accepts the real phrase and repairs it, `rekey` and `confirmRecoveryPhrase` sign keys carrying the typed phrase's key, `recover` opens, and the vault reports `recovery-key-mismatch` (D-56); the same for one a session garbled so it doesn't open (review 032 A); a record served for the held version with another keys hash, naming another recovery key, is refused by `reconcile` and `overview`.
- `test/vectors/recovery-key.v1.json`.

Related threats: TH-10, TH-12, TH-13, TH-37, TH-41.

### SP-24: An invite proof shows the joiner held the invite link

Property: an invite proof in a `member-keys` record verifies only with the join secret of an `invite` record that an owner of that version signed, over exactly those keys and that account. Owners see it as a hint; `reconcile` admits the joiner automatically only when the integration enables `autoApproveInvites`, only for an invite of the current team key version, and only once per invite.

Limit: it proves possession of the link, not identity. Whoever saw the link (the integration's server and mail provider if they delivered it, anyone reading a stored outbox or logs) can make a valid proof (TH-43).

Assumptions: AS-01. The integration keeps invite links out of its own UI and logs.

Status: deferred (D-32). Not claimed by v1.

Verification:
- `test/security/invite-proof.test.ts`: a valid proof; a wrong secret, another account, other keys; an invite of an older version; a second join with one invite.

Related threats: TH-02, TH-04, TH-37, TH-43.

## Credentials and records

### SP-25: An open vault alone can't change the account's credentials

Property: changing the PIN, replacing the recovery phrase and rotating the account key each require a current credential besides the open vault (D-41): the current PIN, verified by one server evaluation, or the phrase, for a PIN change (only the phrase when no PIN is set); the current phrase or the current PIN for a phrase replacement; the current phrase for a rotation, which keeps it. A wrong credential is refused before anything is written.

Limits:
- Whoever holds a current credential can use it (TH-11).
- Whoever also holds the session and can read the account key writes wraps directly, outside the vault; that takeover is seen (the user is locked out) and undone by a support restore (SP-26, TH-45). Through the vault, even a first recovery setup needs the current PIN (D-61).
- Revoking a device needs only an open vault.

Assumptions: AS-01, AS-05.

Verification:
- `test/security/credential-rotation.test.ts`: with only an open vault, changing the PIN, replacing the phrase and rotating are refused and write nothing; each succeeds with the current credential; a PIN check spends one evaluation; with no PIN set, a PIN change needs the phrase. A first recovery setup takes the current PIN (D-61).
- `test/security/account-rotation.test.ts`: a rotation without the phrase is refused; one with it keeps recovery set up.

Related threats: TH-10, TH-45.

### SP-26: A session can't destroy an account's private records

Property: removing, replacing or retiring an account's private record (account key wraps, member keys wraps) archives it: nothing the account's session can ask the server destroys one (D-42). Support can restore a single record, or an account key version with its records, after which the account opens as before.

Limits:
- Until support restores, the account can be locked out or a team unavailable.
- Restores are the integration's support process: the library doesn't check who asks for one.
- Devices that accepted a later account key version refuse a restored older one (SP-07) and must be reset. Owner approvals made in between stay.
- A restore brings back whatever the restored records open: a credential replaced since, or a revoked device (TH-48). The user secures the account after it (D-45).

Assumptions: the server honours rule 7 ([server contract](scope.md#server-contract)).

Verification:
- `test/security/record-archive.test.ts`: a deleted `member-keys-wrap` is restored; a PIN thief replaces the phrase and rotates, and restoring the earlier account key version brings back the user's PIN, phrase, devices and teams; a device that accepted the thief's version reports `rollback`; a session commits a version switch with garbage wraps, and the version restore undoes it. A phrase thief's takeover is restored, and securing with a new phrase leaves the leaked one opening nothing. An open vault with the session deletes the recovery wrap, sets up its own phrase and rotates; restoring the version and the recovery wrap from before brings back the user's phrase (TH-45). Limit: restoring a revoked device's wrap lets that device unlock again. A session's garbage wraps, for a team and outside it, are absent and stop neither the team nor `secureAccount`; the server refuses a wrap without its keys or at another account key version; a wrap that opens with mismatched keys fails its team, and securing still runs (D-58); with such a wrap in another team, or a published record withheld, the warnings list that team under `foreign-member-keys` and a phrase replacement reports it failed, re-keying the others (review 028 A); a store error while listing the teams writes nothing, and a retry re-keys them (review 030 A). A PIN, recovery or device wrap a session replaced with one that doesn't parse costs only that method: `status()` and `warnings()` work, and the PIN change, `secureAccount` with a new PIN, a recovery setup and `recover` replace it (review 035 B). A PIN wrap whose `kdf` the reader refuses, or this device's wrap that doesn't open, costs only that method too: `secureAccount` with a new PIN runs, a bad proof still refuses, and the device registers again (review 037 B, C).

Related threats: TH-10, TH-11, TH-36, TH-45, TH-46, TH-48.
