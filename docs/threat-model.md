# Threat model

> Status: draft, under review. Which review added each threat is recorded in the plans (`.agents/plans/`), not here; the index gives each threat's current disposition.

## Role

Answers: **against whom are we protecting the system?**

Lists what is protected, who may attack it, what the design assumes, and each threat with its disposition: **mitigated** (with the property that mitigates it, in [security-properties.md](security-properties.md)) or **accepted** (with the reason). Scope boundaries come from [scope.md](scope.md); terms are defined there.

## Audience

Security reviewers, architects, maintainers, and anyone deciding whether the library fits their risk.

## Assets

What must stay confidential or intact:

- **Item contents:** texts, files and file names a team encrypts, and submissions sent to an inbox.
- **Team keys:** every version of every team key.
- **Member keys:** each member's private signing and encryption keys for a team.
- **Account keys:** the account key and what protects it: the PIN, the recovery phrase, and device keys.
- **Team trust state:** the chain of team key versions with their owner lists, and which member keys owners approved.
- **Item keys:** each item's own key, including the copy carried by a share link.
- **Inbox private keys:** the keys that open outside submissions. An inbox keeps its key pair for life, so submissions to an inbox created before a member's removal are **not** confidential against that member if they later obtain the ciphertexts (TH-30).

Not protected (see [Non-goals](scope.md#non-goals)): metadata such as team membership, item counts, sizes and timing.

## Threat actors

| Id | Actor | What they have |
| --- | --- | --- |
| A1 | **Data thief** | A copy of the server's database, file storage or backups. Can run offline attacks for as long as they like. |
| A2 | **Malicious server** | Full control of stored records and API responses: can return, hide, replay, reorder or forge records. Does not control the code clients run (assumption AS-02). |
| A3 | **Network attacker** | Can observe and modify traffic. |
| A4 | **Removed member** | Was a member and kept every key they had at removal. |
| A5 | **Malicious member** | A current member acting against the team. |
| A6 | **Owner-key thief** | Holds a current owner's keys for one team. |
| A7 | **Device thief** | Holds a lost or stolen device where the account was unlocked. |
| A8 | **Credential thief** | Learned a user's PIN or recovery phrase (shoulder-surfing, phishing, a captured input). |
| A9 | **Injected script** | Script running inside the application where keys are used (XSS, malicious dependency). |
| A10 | **Outsider** | Anyone outside the team: an inbox sender, a link-share holder, a curious visitor. |
| A11 | **Session thief** | Holds the user's sign-in session with the integration (a stolen cookie or token), but not the PIN or recovery phrase. Can call every API the user can. |

## Trust assumptions

| Id | Assumption |
| --- | --- |
| AS-01 | The cryptographic primitives (libsodium, @noble/curves) are correctly implemented and the platform random generator is secure. |
| AS-02 | Users run the expected library and application code. Delivering it honestly is the integration's job (TH-26). |
| AS-03 | A device is not compromised **while** it is in use (no malware, no malicious browser extension). A device stolen afterwards is in scope (TH-10). |
| AS-04 | TLS protects traffic between clients and the server. |
| AS-05 | The server keeps the OPRF key secret and enforces PIN rate limits ([server contract](scope.md#server-contract), rules 1–2). If not, see TH-09. Whatever answers PIN evaluations without the key can't fake them (TH-51). |
| AS-06 | When an owner confirms a member's request (joining, new keys), they can check it is genuine through a channel the server doesn't control (in person, phone, another messenger). Without fingerprints (D-11) the check confirms the request, not the keys the server shows, which an unproven approval trusts (TH-04). |
| AS-07 | A member can copy every key they were given. Their keys are decrypted in their own browser, which they control: developer tools, a modified script or an extension can read them. Removal only protects what is encrypted with keys they never received. |

## Index

| Id | Threat | Actor | Disposition |
| --- | --- | --- | --- |
| TH-01 | Server reads stored items or keys | A1, A2 | Mitigated: SP-01 |
| TH-02 | Server swaps a member key or adds a fake member | A2 | Mitigated: SP-04 |
| TH-03 | Server forges the owner list | A2 | Mitigated: SP-05 |
| TH-04 | Server impersonates a team or a member at first contact | A2 | Accepted (D-11 deferred); limited by the anchor floor and the vault's anchor to a join, a re-join on a device with no vault anchor, an owner's repair anchor and an unproven re-key: SP-07 (D-48, D-50, D-54, D-59) |
| TH-05 | Server rolls back or hides team state | A2 | Partly mitigated: SP-07 (anchors, anchor floor in the member keys, D-48, D-52); residual accepted |
| TH-06 | Server modifies or moves encrypted items | A2 | Mitigated: SP-03 |
| TH-07 | Offline PIN guessing from a stolen backup | A1 | Mitigated: SP-08 |
| TH-08 | Online PIN guessing with a stolen session | A11, A9 | Mitigated: SP-08 (server rate limit) |
| TH-09 | The server operator brute-forces a PIN | A2 | Accepted |
| TH-10 | Lost or stolen device | A7 | Partly mitigated: SP-10 (revoke only); full remedy `secureAccount`: SP-11 + SP-23; the open vault alone can't take the remedy away: SP-25; with the session too, a takeover is undone by a support restore: SP-26 |
| TH-11 | Leaked PIN or recovery phrase | A8 | Partly mitigated: SP-09, SP-11, SP-19; a takeover is undone by a support restore: SP-26 |
| TH-12 | Account key leaked | A9, A7 | Mitigated: SP-11 + SP-12 + SP-23; past access accepted |
| TH-13 | Member keys of one team leaked | A9, A7 | Mitigated: SP-12 + SP-23; past access accepted |
| TH-14 | Removed member keeps reading | A4 | Mitigated: SP-06, SP-22; history accepted |
| TH-15 | Member forges an item's author | A5 | Accepted in v1 (D-09 deferred) |
| TH-16 | Member reads everything in the team | A5 | Accepted (by design) |
| TH-17 | Stolen owner key takes over a team | A6 | Partly mitigated: SP-05, SP-15; residual accepted |
| TH-18 | Owner loses their credentials | — | Mitigated: SP-16; single-owner team accepted, with no server-side recovery (SP-19) |
| TH-19 | One team's compromise spreads to the user's other teams | A9 | Mitigated: SP-02 |
| TH-20 | Injected script in the account vault | A9 | Accepted; remedy SP-09 + SP-11 + SP-12 |
| TH-21 | Server swaps an inbox key | A2 | Mitigated when the link travels outside the server: SP-14; otherwise accepted |
| TH-22 | Inbox sender reads other submissions | A10 | Mitigated: SP-14 |
| TH-23 | Leaked share link | A10 | Accepted (the link is the capability) |
| TH-24 | Downgrade to an old version or weak algorithm | A2 | Mitigated: SP-17 |
| TH-25 | Malformed records exploit the parser | A2, A5, A11 | Partly mitigated: SP-18; a team key version that fails its checks stops the chain, accepted |
| TH-26 | Server delivers malicious code | A2 | Accepted (out of scope) |
| TH-27 | Metadata exposure | A1, A2 | Accepted (out of scope) |
| TH-28 | Server deletes or withholds data | A2 | Accepted (availability) |
| TH-29 | Network attacker reads or alters traffic | A3 | Mitigated: SP-01, SP-03 |
| TH-30 | Removed member opens new submissions to an existing inbox | A4 with A1 | Accepted in v1 (D-20); remedy: replace the inbox |
| TH-31 | Anyone with an inbox link submits fake content | A10 | Accepted (out of scope) |
| TH-32 | Recorded ciphertexts broken by a future quantum computer | A1, A2 | Accepted in v1 |
| TH-34 | PIN hashing cost set too low | Integration error, A2 | Mitigated: library hard floor (D-17, SP-08) |
| TH-35 | A timestamp shown as proof of when something was sent | A5, A10 | Accepted; integration must not present it as trusted |
| TH-36 | Session thief destroys the account | A11 | Mitigated: SP-09, SP-26 (removed and replaced records archived for a restore window, server contract, D-39, D-42) |
| TH-37 | Session thief injects member keys | A11 | Partly mitigated: SP-12 (pinned approvals), SP-22 (no automatic approval without proof), SP-23 (recovery proof); residual accepted |
| TH-38 | Split view: two records for one version | A6 with A2 | Accepted (needs key transparency) |
| TH-39 | A team's keys reach the wrong context | A9, A3, A2 | Mitigated: SP-02 (sealed transfer); which context receives, and a channel the server can't write, are the integration's |
| TH-49 | A forged transfer opens a forged team | A2, A9 | Accepted: the integration's channel between contexts (SP-02 Limit, D-29) |
| TH-50 | A key holder and the server rewrite or add items or inboxes | A4 or A5 with A2 | Accepted: the server's write-once rule (SP-03 Limit, D-09 deferred) |
| TH-51 | A server front end forges PIN evaluations | A2 then A1 | Mitigated: SP-08 (D-53) |
| TH-40 | The server confirms a stored file from its reference | A2, A1 | Mitigated: SP-21; plain hashes sent by the integration stay its responsibility |
| TH-41 | A leaked recovery phrase replaces a member's keys | A8 | Partly mitigated: owners excluded from auto-approval (SP-23), changes reported (SP-15); race accepted |
| TH-45 | An unlocked vault replaces the account's credentials | A7, A9 | Partly mitigated: SP-25 (D-41) for the open vault alone; with the session too, accepted and undone by a support restore: SP-26 |
| TH-46 | Session thief corrupts private team records | A11 | Mitigated: SP-26 (D-42, D-62, D-63); unavailability until restored accepted |
| TH-47 | Session thief takes a member's key version numbers | A11 | Partly mitigated: SP-12 (D-43); approvals wait until the thief's sessions end; bait keys need a human |
| TH-44 | Session thief spends the PIN budget | A11 with A7, A8 or A9 | Mitigated: SP-11 (phrase-only rotation and securing, D-40); the integration may reset the budget |
| TH-48 | A support restore brings back what an attacker can open | A8, A7, A2 | Accepted: restores are the integration's to authenticate (SP-26 Limit); securing with a new phrase follows (SP-11, D-45) |

Dormant threats, not applicable in v1 (kept so their ids stay stable, and to return with the mechanisms they belong to):

| Id | Threat | Actor | Disposition |
| --- | --- | --- | --- |
| TH-33 | Removed owner signs grants for versions they owned | A4, A6 | Not applicable in v1: no grants (D-37) |
| TH-42 | The server hides grants to suppress a rotation | A2 | Not applicable in v1: no grants; who holds a version is the signed roster (D-37) |
| TH-43 | An invite link leaks | A2, A11, A1 | Not applicable in v1: invite links carry no secret (D-32 deferred) |

---

## Server and storage

A data thief (A1), a malicious server (A2) or a network attacker (A3): what the server stores, serves and relays.

### TH-01: Server reads stored items or keys

Actor: data thief (A1), malicious server (A2).

Attack: reads the stored records and tries to recover item contents or keys.

Impact: every team's items exposed.

Disposition: mitigated by SP-01. The server only ever stores ciphertexts and wrapped keys.

### TH-02: Server swaps a member key or adds a fake member

Actor: malicious server (A2).

Attack: when an owner admits a member or rotates the team key, the server returns its own public key instead of the member's, or adds a member who doesn't exist. This is a classic man-in-the-middle attack on key distribution.

Impact: the owner seals the team key to the server, which can then read every new item.

Disposition: mitigated by SP-04. Owners seal only to member keys they signed, and members open only team keys an owner signed for them. The first time an owner sees a new member's keys, they come from the server: see TH-04.

### TH-03: Server forges the owner list

Actor: malicious server (A2).

Attack: presents a modified chain of team key versions that adds an owner it controls, or lets a removed owner keep signing.

Impact: the fake owner approves fake members (TH-02 succeeds).

Disposition: mitigated by SP-05: each version carries its owner list, is signed by an owner of the previous version and links to its hash, and version numbers are consecutive (D-19, §4.5). A removed owner is in no later owner list, so their signatures are refused for every later version.

### TH-04: Server impersonates a team or a member at first contact

Actor: malicious server (A2).

Attack: the first time a client meets something, it has nothing earlier to compare against. This is the trust-on-first-use (TOFU) problem. The server can:

- present a completely forged team, with fake owners from the start, to a user joining it or opening it on a device with no stored state;
- give an owner its own keys in place of a new member's keys.

Impact: the user trusts fake owners and their fake members, or the owner seals the team key to the server.

Disposition: accepted in v1, by choice: out-of-band fingerprints are deferred (D-11, SP-20). The exposure is limited to the join: every later change is checked against what the client accepted (SP-05, SP-07), and the member keys carry an anchor floor from the join on, so every device of the member starts from it, in either context (D-48, D-50). A joiner whose invite anchor travelled outside the server isn't exposed at all; one without it, or whose link the server delivered, trusts the chain served at join. So does an existing member re-joining without an anchor on a device with no vault anchor, when the server withholds its wraps (D-59); with a vault anchor, the join refuses a chain without it. An owner approving an unproven re-key trusts the keys the server shows, as for a join: proven re-keys don't (review 019 C).

An owner's anchor given to repair a floor (`rekey`, `secureAccount`, D-54) is a second first contact: it replaces every root the vault holds, and nothing authenticates who sent it. One that reaches the user through the server, or from someone posing as an owner, roots the account's devices on the chain it names: with the server, a forged team, or a real older version below a removal the account had verified, whose key the removed member still holds (review 013 C). Accepted as the integration's duty, like the invite anchor: the repair anchor comes from an owner, outside the server. Closing it belongs to the same deferred mechanism as fingerprints (D-11).

### TH-05: Server rolls back or hides team state

Actor: malicious server (A2).

Attack: serves an older part of the chain (one where a removed owner was still an owner), an older `team-state`, or hides a team key rotation from some members, so they keep encrypting with a version the removed member can read.

Impact: a removed owner or member regains influence or access.

Disposition: partly mitigated by SP-07: a client refuses any chain without its anchor and never encrypts with a version older than it, and the server can serve an older `team-state` but not forge one (§4.4, §6.1). Withholding it leaves a device with no local anchor at its member keys' anchor floor, not at first contact, and every anchor must link to the floor, so no `team-state` or local anchor can choose the chain (D-48, D-52). Accepted: a device that has never seen the newer state can be fooled until it does, since a server that controls delivery can always delay news. Withholding a member's re-keyed record from owners delays its approval the same way, and the old keys keep receiving until it is approved. The same holds for a retired account key version on a device with no stored state, or one that last saw it, which matters when someone holds that old key: after `secureAccount`, the attacker (SP-19, TH-12).

### TH-06: Server modifies or moves encrypted items

Actor: malicious server (A2).

Attack: alters a ciphertext, swaps two items or two parts of an item, drops or reorders parts, or moves an item to another team or another key version.

Impact: users see wrong or altered content, or content attributed to the wrong place.

Disposition: mitigated by SP-03. Every ciphertext is authenticated and bound to its team, item and key version.

### TH-24: Downgrade to an old version or weak algorithm

Actor: malicious server (A2).

Attack: serves records that claim an older protocol version or another algorithm, hoping the client takes a weaker path.

Impact: protections bypassed.

Disposition: mitigated by SP-17. Unknown or unsupported versions and algorithms are refused before any cryptographic operation.

### TH-25: Malformed records exploit the parser

Actor: malicious server (A2); a member or joiner (A5), or a session (A11), for the records they can publish.

Attack: sends truncated, oversized or inconsistent records, aiming for a crash, a logic error or partial decryption. A sender or member can also declare a huge part to exhaust a reader's memory. A joiner publishes a `member-keys` record that fails its checks, aiming to stop the team for everyone. A session of an owner's account, or anyone to whom the integration gives the owner capability, publishes a team key version that fails its checks at the next version.

Impact: wrong data accepted, a client tricked into a weaker path, or a client that runs out of memory. A team key version that fails its checks stops the team for every member, for good.

Disposition: partly mitigated by SP-18. Records are validated before any cryptographic operation, decryption never returns partial data, and the buffered API refuses parts above the integration's `maxBufferedSize` before downloading them. A record in a list that fails its checks is left out, so it stops nothing else (D-58). Accepted: a chain can't leave a version out, and a version's identity is written once (scope rule 3), so a version that fails its checks stops the team; the server's check of the caller (rule 8) is the barrier, and a server that can verify the version's signature against the previous version's owners should (integration guide).

### TH-26: Server delivers malicious code

Actor: malicious server (A2).

Attack: serves modified application code that sends keys or plaintext to the server.

Impact: every protection in this document is bypassed.

Disposition: accepted, out of the library's scope (AS-02). This is inherent to E2EE in the browser; the integration addresses it with reproducible builds and published hashes.

### TH-27: Metadata exposure

Actor: data thief (A1), malicious server (A2).

Attack: reads who belongs to which team, how many items exist, their sizes and their timing.

Impact: information about activity, not contents.

Disposition: accepted, out of scope ([Non-goals](scope.md#non-goals)).

### TH-28: Server deletes or withholds data

Actor: malicious server (A2).

Attack: deletes records or refuses to return them.

Impact: users lose access to items or can't complete operations.

Disposition: accepted. The library detects missing or inconsistent records and fails closed (it refuses rather than proceeding unsafely), but it can't force a server to store data.

### TH-29: Network attacker reads or alters traffic

Actor: network attacker (A3).

Attack: intercepts or modifies requests and responses.

Impact: at most what a malicious server could do (TH-01 to TH-06).

Disposition: mitigated by TLS (AS-04) and, independently, by SP-01 and SP-03: traffic carries only ciphertexts, wrapped keys and signed records.

### TH-32: Recorded ciphertexts broken by a future quantum computer

Actor: data thief (A1), malicious server (A2), keeping records for years.

Attack: stores today's records and breaks X25519 later with a large quantum computer ("harvest now, decrypt later"). The symmetric algorithms are not affected in the same way.

Impact: sealed team keys and inbox submissions recorded today become readable later.

Disposition: accepted in v1. Every record names its algorithm suite (SP-17), so a later suite can add a post-quantum key exchange without changing the rest of the protocol.

### TH-38: Split view

Actor: a malicious or stolen owner key (A6) together with a malicious server (A2).

Attack: the owner key signs two different records for the same version, and the server shows each to a different group of members. Each group sees a valid chain.

Impact: members are silently split; each group may admit members or rotate without the other knowing.

Disposition: accepted. It needs an owner key and the server together, since an honest server stores one record per version, and members on different branches can't open each other's new items, so the split surfaces as failures. A full fix needs key transparency, which is out of v1.

### TH-40: The server confirms a stored file from its reference

Actor: the server or a database thief (A2, A1) holding a candidate file.

Attack: the integration sends its server a reference for each part, for deduplication or as an attachment id. If the reference is a plain hash of the content, anyone with a candidate file computes its hash and checks whether it was stored, and sees which items share a file.

Impact: confirmation of a file's presence, and links between items, without decrypting anything.

Disposition: mitigated by SP-21 for references made with `partRef` (D-28). Values the integration computes from plaintext by other means stay its responsibility ([scope.md](scope.md#what-the-integration-does)).

## PIN and recovery phrase

Attacks on the credentials that open the account: guessing, leaking, spending the budget (A1, A2, A8, A11).

### TH-07: Offline PIN guessing from a stolen backup

Actor: data thief (A1).

Attack: takes the PIN-protected wrap of the account key and tries every possible PIN offline. A short PIN has few enough possibilities to search them all.

Impact: the account key and every team the user belongs to.

Disposition: mitigated by SP-08. A guess can't be checked without one evaluation by the server, which the thief can't perform offline.

### TH-08: Online PIN guessing with a stolen session

Actor: a session thief (A11), or an injected script (A9), holding the user's session but not the PIN.

Attack: submits PIN guesses through the server.

Impact: the account key, if a guess succeeds.

Disposition: mitigated by SP-08 and the server's rate limit, one total budget per account whatever the declared purpose (AS-05, rule 2); weak PINs are refused at creation by the integration's rule. Residual, accepted: the session holder can spend the budget and block PIN unlocks for a while, while the recovery phrase still unlocks and registers the device without an evaluation (§5.4).

### TH-09: The server operator brute-forces a PIN

Actor: malicious server (A2), or an attacker who stole both the OPRF key and the database.

Attack: holds the OPRF key and the backup, so it can evaluate guesses itself, offline, with no rate limit.

Impact: the account key of any user with a short PIN.

Disposition: accepted: a short PIN can't resist someone who holds every piece. Integrations reduce the exposure by isolating the OPRF key from the database, or by offering a longer passphrase or a passkey; the 128-bit recovery phrase is not affected. Isolating the key holds against a server that controls the evaluations' answers without it (TH-51).

### TH-11: Leaked PIN or recovery phrase

Actor: credential thief (A8).

Attack: uses the leaked PIN (with a session for the OPRF evaluation) or the leaked recovery phrase to open the account key.

Impact: the account key and every team.

Disposition: partly mitigated by SP-09, SP-11 and SP-19: for a leaked PIN, the user secures the account with a new PIN; for a leaked phrase, with a new phrase as well (D-45), since securing otherwise keeps the phrase. Accepted: a thief who also holds a session can act first, replacing the phrase and rotating (D-41); the remedy is a support restore of the earlier account key version (SP-26, D-42), then securing with new credentials (TH-48).

### TH-51: A server front end forges PIN evaluations

Actor: malicious server (A2) that controls the answers to PIN evaluations but not the OPRF key (a compromised front end before an isolated key service), then a data thief (A1).

Attack: answers enrolment evaluations with a key of its own, or sends writers to a key id it chose, so the PIN wraps written then can be checked offline without the real key.

Impact: an offline guess on the PIN of every account that set or upgraded a PIN in that window, long after the compromise ends.

Disposition: mitigated by SP-08 (D-53): every evaluation carries a proof checked against a public key the client's code pins for the key id, and the key id new wraps use is a client setting, never a server answer. Residual: the front end can still make guesses within each account's budget through the real service (TH-08), and nothing helps if it also serves the client's code (AS-02).

### TH-34: PIN hashing cost set too low

Actor: an integration misconfiguration, or a malicious server (A2) serving a wrap with weak cost parameters.

Attack: a PIN wrap made with a very low Argon2id cost makes each guess cheap, for anyone who can also get OPRF evaluations.

Impact: faster PIN guessing.

Disposition: mitigated. Readers refuse costs outside their bounds, and the library has a hard floor (2 passes, 64 MiB) that no integration setting can go under (D-17, SP-08). The cost is bound into the wrap's associated data, so the server can't change it on an existing wrap.

### TH-41: A leaked recovery phrase replaces a member's keys

Actor: credential thief (A8) holding a member's recovery phrase.

Attack: publishes new member keys signed with the recovery key in every team of the account. Owners' `reconcile` approves them as proven re-keys, and the real member's keys stop receiving new versions. The real member re-keys with the same phrase; the two race.

Impact: the thief reads what the teams write next, and the real member is cut out until a human intervenes. The phrase also opens the account key, so the thief already read everything the account could (TH-11).

Disposition: partly mitigated: owners' re-keys are approved automatically only by the owner's own `reconcile`, for keys its vault holds (SP-23, D-47); a thief who places such keys with the account key the phrase opens already holds the owner key (TH-11), so the phrase gives no new way to change the owner list; each approved re-key is reported (SP-15), and the cut-out member sees `pending` and the `foreign-member-keys` warning (D-43). Accepted: the race itself, which ends when an owner removes the account or approves one set of keys by hand, after the user has secured the account with a new phrase (D-45). A server publishing for the thief isn't bound by rule 8: it can publish a newer proven re-key after each of the user's, or newer keys after an owner's review (`STALE_VERSION`), so against it the race ends only when it stops, as for a session (TH-47).

### TH-44: Session thief spends the PIN budget

Actor: session thief (A11) who could also change the PIN: through an unlocked vault (A7, A9) or a leaked PIN (A8). A session alone only spends the budget (TH-08).

Attack: changes the PIN, then calls the OPRF until the account's budget is spent. Every operation that makes a PIN wrap needs an evaluation, so the user can't replace the PIN, and can't rotate the account key to cut the thief out, until the budget resets (up to the integration's longest window).

Impact: the thief's PIN keeps opening the account, and the thief's devices stay registered, while the user waits.

Disposition: mitigated by D-40 (SP-11): `secureAccount` and `rotate` run with the recovery phrase alone, retire every wrap of the old version (the thief's PIN and devices), and leave the PIN to be set once the budget allows. The integration may also reset the budget through its support process. Residual, accepted: until the budget resets or is reset, the account has no PIN and unlocks with the phrase or a registered device only.

### TH-48: A support restore brings back what an attacker can open

Actor: credential thief (A8) holding a replaced PIN or phrase, device thief (A7) holding a revoked device, or a malicious server or insider (A2).

Attack: asks the integration's support to restore the account key version, or the single wrap, that their credential or device still opens, pretending to be the user. A2 revives archived wraps without asking.

Impact: the replaced credential or the revoked device opens the account again, for as long as the restore window keeps the records.

Disposition: accepted: restores are the integration's support process, and the library doesn't check who asks (SP-26 Limit); the integration authenticates a request by means other than the session or a credential the restore would bring back. After a restore, the user secures the account with a new PIN and, if the restored phrase may be known, a new phrase (SP-11, D-45). A2 reviving wraps breaks rule 7, which revocation relies on anyway (TH-10).

## Devices and the open vault

Someone holding a device or code where keys are used: a device thief (A7) or an injected script (A9). An open vault proves possession of a device, not of the account.

### TH-10: Lost or stolen device

Actor: device thief (A7).

Attack: uses a device where the account was unlocked. Same-device unlocks don't ask for the PIN, so the device can open the account key.

Impact: everything the account can reach, for as long as the device keeps working.

Disposition: partly mitigated by SP-10: a revoked device can't unlock again, which stops a thief who hasn't used it yet, and an inactivity period limits forgotten devices (§5.5). A thief who used the unlocked device may have copied the account key and member keys (D-21); the full remedy is `secureAccount` from a clean device (D-36, SP-11, SP-23), which the open vault alone can't prevent (SP-25); a thief who also holds the session can, and a support restore undoes it (SP-26, TH-45). Accepted: anything already decrypted, and what a team writes before its owners reconcile.

### TH-12: Account key leaked

Actor: injected script in the vault (A9), device thief (A7).

Attack: extracts the account key from memory or storage.

Impact: every team key and item the account can reach.

Disposition: mitigated by SP-11 and SP-12 together, in one operation (`secureAccount`, D-36): rotation alone leaves the member keys the attacker could open, so access ends only when each team approves a re-key (TH-13), which the recovery phrase still proves (SP-23). What the attacker opened before is accepted as lost. Accepted too: the retired version comes back on a device a server serves it to, or after a support restore, and opens with an unchanged PIN or phrase (SP-19): `secureAccount` with a new phrase and a different PIN, and the account's other devices reset, keep it to that. The attacker can also rewrite the recovery public key the recovery wrap names: the vault never uses it when the user types the phrase, reports it, and `secureAccount` repairs it (D-56); accepted, keys made without the phrase meanwhile (`createTeam`, `joinTeam`, an unproven `rekey`) carry the attacker's recovery key, so a server colluding with it can prove re-keys there after `secureAccount`, until an owner approves the user's re-key by hand.

### TH-13: Member keys of one team leaked

Actor: injected script (A9), device thief (A7).

Attack: extracts a member's private keys for one team.

Impact: the attacker can open every team key version given to that member, and sign as that member.

Disposition: mitigated by SP-12: the member gets new keys, approved by an owner in a rotation, so the old keys open nothing new; only the recovery key, never stored, can vouch for the replacement (SP-23). Past versions are accepted as lost.

### TH-19: One team's compromise spreads to the user's other teams

Actor: injected script (A9) running where one team is used.

Attack: script injected in team A's page tries to reach the user's keys for team B, or the account key.

Impact: every team of the user, from one injection point.

Disposition: mitigated by SP-02. A team session receives only that team's keys, directly or through a sealed transfer (TH-39). The protection is as strong as the integration's isolation between the vault and team sessions ([Key custody](scope.md#key-custody)).

### TH-20: Injected script in the account vault

Actor: injected script (A9) running where the account vault runs, or where the PIN or recovery phrase is typed.

Attack: reads the account key, or captures the PIN or phrase as it is typed.

Impact: every team of the user.

Disposition: accepted; it's the integration's job to keep the vault and the credential prompts in the most isolated context it has. Once detected, the remedy is SP-09 (replace the credentials), SP-11 (rotate the account key) and SP-12 (re-key in each team): with the account key, the script could open every member keys bundle, and rotating the account key doesn't change them. It could also plant an anchor floor, or a newest bundle with none; `secureAccount` writes floors only where the floor and the vault's own anchor agree, so a vault that has opened or exported the team refuses it, a vault that never did trusts what it holds, or, with a planted bundle that has no floor, the chain the server serves, and an anchor from an owner repairs it (D-54). With a copied bundle and the session, it can write a readable `team-state` naming a forged anchor; once `secureAccount` re-keys the team, that `team-state` is under keys being replaced and stops nothing (D-63). The vault's anchor is per device: resetting the account's other devices after `secureAccount` leaves only the securing device's, so open or re-key each team there first. With the account key, it can also plant a wrap that opens with keys its published record doesn't match: that team then fails for the account, its repairs included, until support archives the wrap; the account's other teams and its warnings go on, the team listed under `foreign-member-keys` (D-58).

### TH-39: A team's keys reach the wrong context

Actor: injected script (A9) in another page or context, anyone on the channel between contexts (A3), or the server (A2) when the integration relays the channel through it.

Attack: when the vault and team sessions run in separate contexts, the attacker reads one team's member keys in transit, replays a transfer captured earlier, asks the vault for the keys of a team it shouldn't reach, or replaces a receiver's transfer request with its own public key, so the vault seals the keys to it.

Impact: that team's member private keys (the signing key, the encryption key and the `teamStateKey`), in a context the integration didn't intend: the team, and the owner signing key when the member is an owner.

Disposition: mitigated by SP-02. A transfer is sealed to an ephemeral receiver created in the receiving context, names its account and team inside the box, and opens once: reading or replaying it gives nothing (§3.8). Which context may ask for which team is the integration's decision, as is the channel (D-29); a vault that exports to any requester gives away what it exports, and nothing binds a request to the context that made it, so a substituted request receives the keys. Accepted as the integration's duty, as in TH-49: carry the request on a channel the server can't write. A transfer forged for the receiver is TH-49.

### TH-49: A forged transfer opens a forged team

Actor: malicious server (A2) that also carries the channel between contexts, or a script (A9) that can post on it together with a malicious server.

Attack: reads the transfer request, publishes `member-keys` of its own under the member's account, serves a forged chain rostering them, withholds `team-state`, and seals those keys, with a floor pointing at its chain, to the request. `seal` doesn't authenticate its sender (§3.2).

Impact: the receiving context opens the forged team `ready`, and what it writes there is readable by the attacker.

Disposition: accepted, as the integration's duty (SP-02 Limit, D-29): carry the request and the transfer on a channel the server can't write, for example `postMessage` with origin checks or a `MessageChannel`, never relayed through the server. Authenticating the vault would need a secret both contexts already share, which they don't have. With an honest server, injected keys are in no roster: the session is `pending` or `unverified`, never forged.

### TH-45: An unlocked vault replaces the account's credentials

Actor: device thief (A7) or injected script in the vault (A9), holding an open vault but no credential. Same-device unlocks need none.

Attack: replaces the recovery phrase, changes the PIN, or rotates the account key, so the user's credentials stop working and `secureAccount` can't run.

Impact: account takeover: the user loses the account and every team only it could open.

Disposition: partly mitigated by SP-25 (D-41): through the vault, each of these needs a current credential besides the open vault. Through the vault, a first recovery setup needs the current PIN too, so deleting the recovery wrap no longer opens a setup without a credential (D-61). Accepted: a thief who also holds the session, as a script in the vault normally does through the vault's own store, writes wraps directly with the account key it can read; the user is locked out, so it is seen, and a support restore undoes it (SP-26, D-42). Residual, accepted too: the thief can still revoke the user's other devices, which register again with the PIN or the phrase; publish unproven re-keys, which only a human approves (TH-37); or leave teams, which support undoes from the archive (TH-46).

## Sessions

Someone holding the user's sign-in session with the integration, but no credential (A11): they can call every API the user can.

### TH-36: Session thief destroys the account

Actor: session thief (A11).

Attack: calls "change PIN", "replace recovery phrase" and "revoke device", or switches the account to a new account key version, supplying garbage wraps. The server can't tell a garbage wrap from a valid one, so it removes the old ones. The user loses every way to unlock the account. No server-side recovery exists by design.

Impact: permanent loss of the account and of every team key only it could open.

Disposition: mitigated by SP-26 and the server contract (rule 7, D-39, D-42): the server archives every removed or replaced wrap for a restore window, and support restores the generation from before the theft. The old credential stops working as soon as its wrap stops being served (SP-09). Residual, accepted: a data thief (A1) finds the archived wraps, which still need the old PIN with a server evaluation, or the old phrase.

### TH-37: Session thief injects member keys

Actor: session thief (A11).

Attack: publishes member keys under the victim's account in a team: a join before the victim joins, or a "re-key" request. An owner who trusts the name approves them. Or creates a team under the account, with its own keys as the owner's, and invites people as the user.

Impact: the attacker reads the team from that rotation on.

Disposition: partly mitigated: only a re-key signed by the member's recovery key is proven, which a session can't produce (SP-23); approvals hold for exactly the reviewed keys, and `reconcile` never approves an unproven one (SP-12, SP-22); keys the member's vault didn't make can't block it (D-43, TH-47), and are reported for the teams where the vault holds keys; `secureAccount` with the product's `teamIds` reports a listed team where it holds none (D-60). Accepted: keys published, or a team created, under the account where the vault holds no keys go unreported, since a session acts as the user in the product (review 030 C); an owner who approves an unproven request without the out-of-band check (AS-06); invite proofs, which would cover first joins, are deferred (D-32).

### TH-46: Session thief corrupts private team records

Actor: session thief (A11); for a readable `team-state`, a holder of a `teamStateKey` (A9 in a context that holds the team, A7).

Attack: writes a well-formed `team-state` whose content is garbage (the server can't check it), deletes the account's `member-keys-wrap` records or replaces them with garbage, or creates garbage wraps under new identities; with a `teamStateKey`, writes a readable `team-state` whose anchor isn't on the team's chain.

Impact: for keys with no floor, every device of the account stops at `TRUST_FAILURE` (`state_unreadable`) for that team; with a floor, a `team-state` that doesn't open under the newest keys is absent, and one in a known version is replaced at the next open (D-62, D-63); one at an unknown version stays absent until restored. A readable one off the chain gives `state_conflict` or `rollback` (D-52). Deleted wraps lose the account its keys for the team. A deleted `team-state` sends a new device back to its member keys' anchor floor (D-48, D-50).

Disposition: mitigated by SP-26 (D-42): the server archives every replaced or removed private record, and support restores it. A wrap that doesn't open is absent (D-58), so a created one stops nothing, and the server creates wraps only with their published keys or in a rotation; a replaced one looks like a deletion. Residual, accepted: until support acts, the team is unavailable to the account, an availability loss like TH-28.

### TH-47: Session thief takes a member's key version numbers

Actor: session thief (A11).

Attack: publishes `member-keys` records under the victim's account at the versions the member's next join or re-key would use.

Impact: the member's own write collides forever (`STALE_VERSION`): no join, and no re-key, including those of `secureAccount`.

Disposition: partly mitigated by SP-12 (D-43): new keys take the newest published version plus one, the server accepts keys only from their account at its next version, and the vault reports keys it didn't make, for the teams where it holds keys (`foreign-member-keys`). The bait keys stay unproven, so only a human approves them (TH-37). Accepted: only the newest keys can be approved, so while the thief keeps the session, bait published after each of the member's keys leaves them unapprovable; the integration ends the account's other sessions, as `secureAccount` requires (§5.11).

## Members and owners

Current, removed and malicious members, and stolen owner keys (A4, A5, A6).

### TH-14: Removed member keeps reading

Actor: removed member (A4).

Attack: keeps the team keys they held and reads items, including new ones.

Impact: continued access after removal.

Disposition: mitigated by SP-06 for items and inboxes created after the next rotation, which an owner's `reconcile` runs once the account leaves the integration's active list; rotations keep an allowlist, so forgetting someone removes them (SP-22, §6.6). Accepted: what the member could read before (AS-07), inboxes created earlier (TH-30), the gap a later re-admission opens (D-07), and a server (A2) that keeps listing the removed member as active, which keeps them in with no roster change to report (SP-22 Limit).

### TH-15: Member forges an item's author

Actor: malicious member (A5).

Attack: creates an item that claims another member wrote it.

Impact: false attribution, for example a fake instruction attributed to an owner.

Disposition: accepted in v1. Author signatures are deferred (D-09, SP-13): any member can claim any author. The server alone can't change the author recorded on an item (SP-03); with a key holder it can (TH-50).

### TH-50: A key holder and the server rewrite or add items or inboxes

Actor: a member, or a member removed since, who held a team key version (A5, A4), together with the server (A2) or a server authorization bug.

Attack: builds an `item` record at a version they held, for an existing item id or a new one, with any `createdBy` and new parts, and has the server serve it in place of the real record or as a new item. The same works for an `inbox` record, with a key pair of their own.

Impact: every member opens the replaced or added item as genuine, after the attacker's removal too: forged content, attributed to anyone. A replaced inbox doesn't affect its existing links, whose senders seal to the key in the link; a link built from the stored record would give the attacker the submissions.

Disposition: accepted in v1. Readers open an item at any version their chain holds, so only the server's write-once and current-version rules (§11) keep such a record out (SP-03 Limit). Author signatures (D-09) wouldn't stop it, since the author was in that version's roster; it needs an order the server can't fake, such as key transparency or an owner-signed item index.

### TH-16: Member reads everything in the team

Actor: malicious member (A5).

Attack: reads every item of the team, including items unrelated to their work.

Impact: the team's items, within the team.

Disposition: accepted by design. The team is the encryption boundary; finer boundaries are a non-goal ([scope.md](scope.md#non-goals)).

### TH-17: Stolen owner key takes over a team

Actor: owner-key thief (A6).

Attack: uses the owner's keys to admit members they control, or to remove the other owners.

Impact: reads future items; may lock out the honest owners.

Disposition: partly mitigated by SP-15, detection rather than prevention: every owner and roster change is reported on every member's client (D-44), under the account the keys belong to (D-46), but the attacker can act before anyone reads it. The honest owners remove the stolen key while still owners (SP-05), or else start a new team out of band, and automatic approvals never change the owner list (SP-23, TH-41). Accepted: one stolen owner key is enough for a takeover (D-06), and the removed owner's warning (§6.7) can be washed out by a later rotation.

### TH-18: Owner loses their credentials

Actor: none; this is an availability failure.

Attack: an owner loses both their PIN and recovery phrase, or leaves.

Impact: if nobody else can act as owner, nobody can admit members or rotate the team key ever again. The team is frozen.

Disposition: mitigated by SP-16 for teams with two or more owners; a single-owner team is accepted with a warning, and the only owner can't leave (`LAST_OWNER`) or be deleted by the integration. No server-side recovery exists: it would be a backdoor (SP-19).

### TH-30: Removed member opens new submissions to an existing inbox

Actor: removed member (A4), together with access to the ciphertexts: a data thief (A1), an insider, a server authorization bug, or a current member passing data on.

Attack: an inbox's private key is wrapped by the team key version current when the inbox was created, and its public key is in the link. A member removed later still holds that version, and may have copied the inbox private key itself (AS-07). Senders keep sealing to the same public key, so the removed member can open every later submission to that inbox once they obtain the ciphertexts.

Impact: confidentiality of submissions sent after the removal, to inboxes created before it. The integration's access control is the only barrier; a database leak alone is enough to break it.

Disposition: accepted in v1 (D-20): rotating the team key doesn't help, only a new key pair, which means a new link. The library offers "replace inbox", and integrations bound the exposure with inbox lifetimes and a replacement after a member leaves. Signed rotating inbox keys can close it later without changing links (D-20).

### TH-35: A timestamp shown as proof of when something was sent

Actor: malicious member (A5), outside sender (A10).

Attack: writes any `createdAt` value: backdates an item, or post-dates a submission to look on time.

Impact: misleading dates, if the integration presents them as trustworthy.

Disposition: accepted: timestamps are authenticated, so the server can't change them, but the writer chooses them, and the protocol never uses them for a security decision. Integrations must not present them as a trusted time, and use their server's receive time when one matters (§1).

## Outsiders

Inbox senders and link holders (A10).

### TH-21: Server swaps an inbox key

Actor: malicious server (A2).

Attack: an outside sender has no team keys to check anything against. If the sender gets the inbox public key from the server, the server can hand over its own key instead.

Impact: the server reads the submission.

Disposition: the inbox link carries the inbox public key itself, in the URL fragment, which browsers don't send to the server. When the link reaches the sender outside the server (the team sends it from its own email, chat or website), the sender seals to the right key: mitigated by SP-14. When the server delivers the link (for example a notification email sent by the product's own server), the server can change the key in the link: accepted, because an anonymous sender can't authenticate anything the server alone provides.

### TH-22: Inbox sender reads other submissions

Actor: outsider (A10) with an inbox link.

Attack: uses the inbox link to read other people's submissions.

Impact: submissions of other senders exposed.

Disposition: mitigated by SP-14. A sender only has the public key and their own content key; each submission is sealed with a fresh content key that only the team can open.

### TH-23: Leaked share link

Actor: outsider (A10) who obtains a share link.

Attack: opens the link.

Impact: the shared item.

Disposition: accepted (D-22): the link is the capability, for reading and, with whoever serves the record, for what other recipients of the link see: members refuse such a record (§7.3), and expiry or one-time viewing are the integration's server-side controls. The library keeps the key out of what the server sees when the link carries it in the URL fragment under the share-link checklist ([scope.md](scope.md#what-the-integration-does)). The key does reach a server when the integration's own server sends the link (as in TH-21), or when an email security service rewrites links, fragment included.

### TH-31: Anyone with an inbox link submits fake content

Actor: outsider (A10).

Attack: sends content that pretends to come from someone else, or sends a large volume of submissions.

Impact: misleading or unwanted submissions.

Disposition: accepted, out of scope. Inbox submissions are anonymous by design: the protocol protects their confidentiality, not the sender's identity. Rate limiting and abuse handling belong to the integration.

## Dormant threats

Not applicable in v1: they describe mechanisms v1 removed or deferred, and return if those come back (D-32, D-37).

### TH-33: Removed owner signs grants for versions they owned

Actor: removed owner (A4), or someone holding their stolen key (A6).

Attack: after removal, signs a grant of a version they were an owner of, for example to a fake member.

Impact: the fake member opens that version and every earlier one.

Disposition: not applicable in v1. There are no grants (D-37): a version is held only through the roster of its own record, and a removed owner isn't in the owner list of any version after their removal, so they can't sign one (SP-05). They still hold the versions they had (AS-07).

### TH-42: The server hides grants to suppress a rotation

Actor: malicious server (A2).

Attack: hides a removed member's grant from the list an owner reads, so the owner's client doesn't see that a removed account still holds the current version, and never rotates.

Impact: the removed member keeps reading new items.

Disposition: not applicable in v1. Who receives a version is the roster signed inside the version record (D-34), which the server can't edit or trim, and since D-37 it is the only way to hold a version: there is no grant to hide.

### TH-43: An invite link leaks

Actor: the integration's server or mail provider (A2), a session thief who can see the invite in the product (A11), a data thief reading a stored outbox or logs (A1).

Attack: uses a join secret in the invite link to publish keys with a valid invite proof under the invitee's account.

Impact: the owner sees a proof that doesn't mean what it claims, or, with automatic approval, the attacker is admitted.

Disposition: not applicable in v1: invite proofs are deferred (D-32), and an invite link carries only the team's anchor, which is not a secret (§6.4). The threat returns with D-32.
