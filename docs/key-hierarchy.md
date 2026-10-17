# Key hierarchy

> Status: draft, under review. Builds on the decisions in [decisions.md](decisions.md).

## Role

Answers: **how are keys organized, distributed, and managed?**

Shows each key's job, what protects it, and what happens to it when people join, leave, lose a device or suspect a leak. [security-properties.md](security-properties.md) says what must hold; this document shows which keys make it hold. Exact algorithms, encodings and steps are in [protocol.md](protocol.md). Terms are defined in [scope.md](scope.md#vocabulary).

## Audience

Implementers, maintainers, security auditors.

## Principles

1. **Random and wrapped, not derived.** A key that may need to change on its own is random and stored wrapped (encrypted) by the key above it (D-04). Only keys computed from something the user types (PIN, recovery phrase) are derived.
2. **One job per key.** A signing key never encrypts; an encryption key never signs; a key that wraps account material never wraps content.
3. **Every ciphertext names its context.** A wrapped key or an encrypted part is authenticated together with where it belongs (account, team, item, part, version). Moved elsewhere, it fails to open (SP-03).
4. **Owners sign, members verify.** Every team key a member opens, and every member key an owner seals to, traces back to an owner's signature. Every owner traces back to the team's chain of team key versions, which lists the owners of each version (SP-04, SP-05).
5. **The server stores only ciphertexts, public keys and signatures** (SP-01).
6. **The application never holds a raw key.** Keys stay inside the library; the application passes plaintext in and gets plaintext and link strings out (D-15).

## The tree

```text
ACCOUNT  (one per person)
  PIN ──Argon2id + server OPRF──► pinKey ──────┐
  recovery phrase ──BIP-39──► recoveryKey ─────┤ each wraps the same
  deviceKey (one per registered device) ───────┘ accountKey (versioned)
                                                    │ wraps
                                                    ▼
TEAM MEMBERSHIP  (one bundle per account and team)
  memberKeys = { signing key (Ed25519), encryption key (X25519), teamStateKey }
     │ public halves published; an owner approves them by granting a team key
     ▼
TEAM  (one per team)
  teamKey v1 ◄── v2 ◄── v3 …     one signed chain: each version lists its owners,
                                 links to the previous record's hash, and wraps
                                 the previous key (D-07, D-19)
     │ each version sealed to members' encryption keys, in owner-signed grants
     ▼
CONTENT
  itemKey (one per item)           wrapped by a teamKey version; may travel in a share link
  inbox key pair (one per inbox)   private key wrapped by a teamKey version; public key in the inbox link
     └─ contentKey (one per submission)   sealed to the inbox public key by the sender
```

## Account keys

These keys live in the account vault ([Key custody](scope.md#key-custody)). A team session never receives them.

### `accountKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the account's member keys bundle for every team. Top of the account. |
| Algorithm | 256-bit symmetric key, used with XChaCha20-Poly1305. |
| Generation | Random, on the client, at account setup and at each rotation. Versioned: 1, 2, … |
| Storage | Never in clear. The server stores one wrap per unlock method: the PIN, the recovery phrase, and each registered device. |
| Access | The account vault only. |
| Rotation | On demand: after a device loss, a suspected leak or a credential leak. Re-wraps every member keys bundle; member keys themselves don't change, so no team notices (SP-11). |
| Recovery | Through any unlock method. |
| Destruction | Wraps of a retired version are deleted by the server after rotation ([server contract](scope.md#server-contract), rule 7). |

### `pinKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the `accountKey` for the PIN. |
| Algorithm | Argon2id over the PIN; then an OPRF evaluation by the server with a key specific to this account (RFC 9497, ristretto255-SHA512); then keyed BLAKE2b combining both. 256-bit result. |
| Generation | Derived each time the user types the PIN. Each derivation costs one rate-limited server evaluation. |
| Storage | Never stored, not even on the device (D-05). |
| Access | Whoever knows the PIN **and** gets a server evaluation for this account. |
| Rotation | On PIN change: a new wrap replaces the old one. |
| Recovery | Not needed: a lost PIN is replaced through the recovery phrase. |
| Destruction | The server deletes the old wrap after a PIN change. |

### `recoveryKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the `accountKey` for the recovery phrase. Used when the PIN is lost or no device is left. |
| Algorithm | 12-word BIP-39 phrase (128 bits of entropy) → BIP-39 seed → keyed BLAKE2b. 256-bit result. |
| Generation | The phrase is generated on the client and shown once. The user keeps it outside the product. |
| Storage | Never stored by the library or the server. |
| Access | Whoever holds the phrase. |
| Rotation | When the user replaces the phrase, and at each account key rotation unless the user enters the current phrase again (D-10). |
| Recovery | None. Losing the phrase and every other unlock method loses the account. |
| Destruction | The server deletes the old wrap after a replacement. |

### `deviceKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the `accountKey` for one registered device, so that device unlocks without the PIN. |
| Algorithm | 256-bit symmetric key, used with XChaCha20-Poly1305. |
| Generation | Random, on the device, when it registers (right after a PIN or recovery unlock). |
| Storage | On the device only, through `LocalKeyStore`. The browser adapter keeps it wrapped by a non-extractable WebCrypto key, so it can't be copied off the device as a file. |
| Access | Code running on that device. |
| Rotation | None. A device whose wrap was removed registers again with a new `deviceKey`. |
| Recovery | None. A lost device is replaced by registering a new one. |
| Destruction | Revocation: the server deletes the device's wrap. An account key rotation also makes every other device's wrap useless; those devices register again (D-10). |

## Team membership keys

An account has one bundle of member keys per team. Bundles of different teams are independent: holding one says nothing about another (SP-02). The account vault opens the bundle of one team and hands it to that team's session.

### Member signing key

| Attribute | Value |
| --- | --- |
| Purpose | Signs this member's public keys record and, if the member is an owner, owner actions: team key version records (which carry the owner list) and grants. |
| Algorithm | Ed25519. |
| Generation | Random, on the client, when the account joins the team or re-keys. |
| Storage | Private half: in the member keys bundle, wrapped by the `accountKey`. Public half: in the member keys record, published. |
| Access | That team's session. |
| Rotation | On re-key after a suspected leak (SP-12). An owner must approve the new keys. |
| Recovery | Through the `accountKey`. |
| Destruction | The old bundle is deleted after a re-key. |

### Member encryption key

| Attribute | Value |
| --- | --- |
| Purpose | Receives team key versions: owners seal each version to it in a grant. |
| Algorithm | X25519 key pair. |
| Generation | With the signing key, in the same bundle. |
| Storage | As the signing key. |
| Access | That team's session. |
| Rotation | With the signing key. |
| Recovery | Through the `accountKey`. |
| Destruction | With the signing key. |

### `teamStateKey`

| Attribute | Value |
| --- | --- |
| Purpose | Encrypts this member's copy of the team state on the server: its anchor, the newest team key version record it verified (SP-07). A new device starts from that anchor instead of trusting the server on first use. |
| Algorithm | 256-bit symmetric key, used with XChaCha20-Poly1305. |
| Generation | Random, in the member keys bundle. |
| Storage | In the member keys bundle. |
| Access | That team's session. |
| Rotation | With the member keys. |
| Recovery | Through the `accountKey`. |
| Destruction | With the member keys. |

## Team keys

### `teamKey`

| Attribute | Value |
| --- | --- |
| Purpose | Protects the team's content: wraps item keys and inbox private keys. |
| Algorithm | 256-bit symmetric key, used with XChaCha20-Poly1305. Versioned: 1, 2, … |
| Generation | Random, on an owner's client, when the team is created and at each rotation. A new version is never derived from the previous one. |
| Storage | Never in clear. Each version is sealed to each member's encryption key, in a grant signed by an owner. From version 2 on, each version's record also stores the previous version wrapped under itself (D-07), and every record lists the owners for that version (D-19). |
| Access | Members holding a grant for that version or a later one. |
| Rotation | After a member is removed (when the integration decides), at every owner change (always, D-13), or after a suspected leak. |
| Recovery | Any member with a grant for the current version can open every version. If no member can unlock their account any more, the team's keys are lost. |
| Destruction | None in v1: earlier versions are kept so history stays readable. |

## Content keys

### `itemKey`

| Attribute | Value |
| --- | --- |
| Purpose | Encrypts every part of one item. Derives the item's part reference key (SP-21). |
| Algorithm | 256-bit key for XChaCha20-Poly1305 secretstream (a streaming mode that handles content of any size in chunks). |
| Generation | Random, inside the library, when an item draft starts (D-27). |
| Storage | Wrapped by the team key version current when the draft is sealed, in the item's `item` record, a key record in the key store. That record also lists the item's parts (the manifest, D-16), authenticated with the wrap. The parts themselves are content, stored by the integration (D-25). |
| Access | Members who can open that team key version, and anyone holding a share link to the item. |
| Rotation | None. Items never change: new content is a new item with a new key, so content written after a rotation never uses a key a removed member could hold. |
| Recovery | Through the team key. |
| Destruction | When the integration deletes the item's records. A copy given in a share link can't be taken back. |

### Inbox key pair

| Attribute | Value |
| --- | --- |
| Purpose | Lets outside senders seal submissions that only the team can open. |
| Algorithm | X25519 key pair. |
| Generation | Random, inside the library, when a member creates the inbox. |
| Storage | Public key: in the inbox record and in the inbox link. Private key: wrapped by the team key version current at creation, with the public key in the wrap's context. Only a holder of that team key can produce the wrap, so it also proves a member created the inbox. |
| Access | Private key: members who can open that team key version. Public key: anyone with the link. |
| Rotation | None automatic in v1: the key pair lives as long as the inbox, so a member removed later can open later submissions if they obtain the ciphertexts (TH-30, D-20). Replacing the inbox (a new key pair and a new link) ends that; the integration decides when. Signed rotating inbox keys, which keep the link, are recorded for a later version (D-20). |
| Recovery | Through the team key. |
| Destruction | When the integration deletes the inbox. |

### Submission `contentKey`

| Attribute | Value |
| --- | --- |
| Purpose | Encrypts every part of one submission (D-14). Derives the submission's part reference key (SP-21). |
| Algorithm | 256-bit key for XChaCha20-Poly1305 secretstream. |
| Generation | Random, inside the library on the sender's side, when a submission draft starts. |
| Storage | Sealed to the inbox public key, inside the submission envelope, together with the submission's list of parts. The envelope and parts are content, stored by the integration (D-25). |
| Access | Whoever can open the inbox private key. The sender holds it only while submitting. |
| Rotation | None: one key per submission. |
| Recovery | Through the inbox private key. |
| Destruction | With the submission. |

### Part reference key

| Attribute | Value |
| --- | --- |
| Purpose | Computes `partRef` references, safe to send to the integration's server (D-28). |
| Algorithm | Keyed BLAKE2b-256, derived from the item key or submission content key with its own label (§3.9). |
| Generation | Derived when a reference is asked for; one job per key, so the content key itself never hashes content. |
| Storage | Never stored. |
| Access | Holders of the item key or content key. |
| Rotation | None: lives and dies with its item or submission. |
| Recovery | Re-derived. |
| Destruction | With its item or submission. |

## Moving a team's keys between contexts

### Transfer receiver key

| Attribute | Value |
| --- | --- |
| Purpose | Receives one team's member keys from the vault, when the vault and the team session run in separate contexts (D-29). |
| Algorithm | X25519 key pair; the transfer is a sealed box (§3.8). |
| Generation | Random, inside the library, in the receiving context, for one transfer. |
| Storage | Memory only, in the receiving context; the public half goes to the vault through the integration's channel. |
| Access | The receiving context. |
| Rotation | None: one per transfer. |
| Recovery | None: create another receiver. |
| Destruction | Wiped once the transfer is opened. |

The account key never takes part: the vault opens the team's member keys bundle and seals it to the receiver. Only that team's keys travel.

## Signed records and the owner rule

Three kinds of records carry signatures. They hold no secret, but they decide which keys are trusted.

| Record | Signed by | Says |
| --- | --- | --- |
| **Member keys record** | The member's own signing key | "These are my signing and encryption public keys for this team." The self-signature proves the two keys belong together. It doesn't prove who the member is: an owner approves that by granting. |
| **Team key version record** | An owner of the previous version (version 1: its own creator, listed as owner) | "Version n of this team's key exists; its owners are this list; the previous record has this hash; here is version n−1 wrapped under it." The records form one chain that can't be edited, and that chain is also the history of owners (D-19). |
| **Grant** | An owner of that version | "Member M, with these public keys, receives team key version n; here it is, sealed to M's encryption key." |

`item` and `inbox` records aren't signed. Their wrap under the team key, with their context, already proves a member created them; signing for authorship is deferred (D-09).

**The owner rule.**
- A grant for version n is valid only if its signer is in the owner list of version n.
- A version record n is valid only if its signer is in the owner list of version n−1.

Each owner's signing key must also be the one in that account's published member keys record, so "bob became an owner" really is about Bob's key (SP-15). That's a direct lookup, with nothing to compute. Every owner change (add, remove, replace a key) creates a new version (D-13), so a version's owner list never changes once written, and version numbers are consecutive: nobody chooses them.

A removed owner isn't in the owner list of any later version, so their signatures are refused for all of them. They can still sign grants for versions they owned, whose keys they already hold. Such grants are never carried into a rotation, which only carries members holding a grant for the current version (TH-33).

## Who can open what

The blast radius of each leak, and its remedy:

| If this leaks… | …the attacker can open | Remedy |
| --- | --- | --- |
| A PIN (with the user's session) | The `accountKey`, and everything under it | Change the PIN; rotate the account key if it may have been used (SP-09, SP-11) |
| A recovery phrase | Same as a PIN, without needing the server | Replace the phrase; rotate the account key (SP-09, SP-11) |
| A device, not used by the attacker | Nothing yet | Revoke the device (SP-10) |
| A device, used by the attacker while unlocked | The `accountKey` and the member keys of every team the device opened | Revoke the device, rotate the account key, re-key in each affected team (SP-10, SP-11, SP-12; D-21) |
| The `accountKey` | Every member keys bundle of the account, so every team key the account can reach | Rotate the account key **and** re-key in each team: rotation alone doesn't change member keys (SP-11, SP-12) |
| One team's member keys | Every version of that team's key granted to the member, and every earlier version | Re-key in that team, approved by an owner, then rotate the team key (SP-12) |
| One `teamKey` version | That version, every earlier one, their items and inboxes | Rotate the team key; replace inboxes (SP-06, TH-30) |
| One `itemKey` | That item only | Delete the item if appropriate |
| One inbox private key | Every submission to that inbox, including later ones (TH-30) | Replace the inbox |
| One `contentKey` | That submission only | None |

A leak never crosses a branch of the tree: one team's keys never open another team's, and nothing below the `accountKey` opens it.

## Lifecycle scenarios

Each scenario lists what changes and what old key material can still open afterwards. [protocol.md](protocol.md) gives the exact steps.

### Setting up an account

1. Generate `accountKey` version 1.
2. The user chooses a PIN: derive `pinKey` (one server evaluation) and store the PIN wrap.
3. Generate a recovery phrase, show it once, derive `recoveryKey` and store the recovery wrap.
4. Register this device: generate `deviceKey`, keep it locally, store the device wrap.

### Adding a device

1. On the new device, the user enters the PIN (or the recovery phrase), which opens the `accountKey`.
2. The device registers: a new `deviceKey` and a new device wrap.

Other devices are not affected.

### Losing the PIN

1. The user enters the recovery phrase, which opens the `accountKey`.
2. The user chooses a new PIN. The new PIN wrap replaces the old one.

### Changing the PIN or replacing the recovery phrase

1. Open the `accountKey` with any unlock method.
2. Store the new wrap. The server deletes the old one after a short delay; the old credential works until then (SP-09).

A copy of the old wrap taken before the deletion still opens the current `accountKey` with the old credential. If that's a concern, also rotate the account key.

### Losing a device (D-21)

Two cases:

- **Not used by anyone** (locked, wiped, or nobody opened the app). From another device, or after recovery, revoke it. The server deletes its wrap, and the device can't unlock again (SP-10). Nothing else is needed.
- **Possibly used while unlocked.** Assume the attacker copied the `accountKey` and the member keys of every team the device opened. Revocation alone doesn't evict them, because every new team key version is still sealed to those member keys. The full remedy:
  1. revoke the device;
  2. rotate the account key (SP-11);
  3. re-key in each affected team, each approved by an owner, followed by a team key rotation (SP-12).

  After that, the copied keys open nothing written afterwards. The library offers each step; the integration decides whether to guide users through them.

### Rotating the account key (D-10)

1. Open the current `accountKey`.
2. The user enters the PIN (one server evaluation), and either enters the recovery phrase or receives a new one.
3. Generate the next `accountKey` version and re-wrap every member keys bundle under it.
4. Store the new PIN, recovery and current-device wraps, and switch the account to the new version in one atomic step.
5. The server deletes every wrap of the old version. Other devices ask for the PIN once to register again.

Member keys don't change, so teams see nothing. The old `accountKey` only opens records that the server has deleted (SP-11). For the same reason, rotation alone doesn't end team access for someone who already copied a member keys bundle; that takes a re-key in each team (SP-12).

### Creating a team

1. The creator's vault generates their member keys for the team.
2. They generate `teamKey` version 1 and its record (owners: themselves), and a grant of version 1 to themselves.
3. Both are stored in one atomic batch, so a team never exists half set up.

### Joining a team

1. The joining account's vault generates member keys for the team, stores the bundle wrapped by its `accountKey`, and publishes its member keys record. (Anything that wraps member keys runs in the vault.)
2. An owner checks the request is genuine (AS-06) and stores a grant of the current version to those keys.
3. The new member opens the current version from the grant, and every earlier version by walking the chain (D-07).

Until the grant exists, the member is *pending*.

### Removing a member

1. The integration removes the member's access on its server.
2. An owner rotates the team key, now or later as the integration decides.

The removed member keeps every key they had (AS-07): every version up to the rotation, and their items and inboxes. They can't open the new version, or items and inboxes created with it (SP-06), unless they are granted a later version again; the chain then opens the gap too. Inboxes created earlier stay open to them, if they obtain the ciphertexts, until replaced (TH-30).

### Rotating the team key

1. An owner of the current version n opens it.
2. Recipients: the accounts the owner keeps (an explicit list, normally the active members) that hold a valid grant for version n. Anyone left off the list gets nothing, so forgetting someone costs access instead of leaking it.
3. Generate version n+1. Its record lists the owners (unchanged, unless this rotation changes them), links to version n's record, and wraps version n under the new key.
4. Store the version record and the owner's own grant in one atomic batch; this makes n+1 current.
5. Store grants for the other recipients. If interrupted, the owner resumes by granting n+1 to recipients still missing it.

### Changing the owners: add, remove, replace a key (D-13)

Every owner change is a rotation whose new version carries the new owner list. The version record and the signer's grant are written in one atomic batch, so the change is never half applied.

- **Adding an owner:** the new owner must already be a member with a grant for the current version.
- **Removing an owner:** members whose newest grant was signed by the removed owner are shown to the rotating owner as a warning before they receive the new version. It's a warning, not a guarantee: a later grant by another owner hides that origin.
- After removal, the removed owner's signatures are refused for every later version.

### An owner loses their credentials

1. Another owner removes them from the owner list (previous scenario).
2. The person recovers their account, or sets up a new one, and joins again with new member keys.
3. An owner grants them the current version and, if wanted, adds them back as an owner.

A team with a single owner can't do this. Nobody can manage the team any more (TH-18).

### Re-keying after a suspected leak of member keys

1. The member's vault generates new member keys for the team and publishes them. Until step 2, the member keeps reading with the old keys.
2. An owner checks the request is genuine and rotates the team key, approving the new keys: the new version is sealed to them, and the old keys receive nothing. A signature by the old keys is never enough, since the attacker may hold them (SP-12). If the member is an owner, the same rotation replaces their signing key in the owner list.

One rotation does it all: the chain gives the new keys every earlier version, and a rotation only ever carries one set of keys per account, the newest approved one.

### Leaving a team

1. The member's vault deletes its wrapped member keys and its team state for the team.
2. The remaining owners rotate the team key without the member in the keep list, when the integration decides (as for a removal).

The only owner can't leave: the library refuses (`LAST_OWNER`) until another owner is added. Otherwise the team would freeze (TH-18).

### Deleting an account

Every record private to the account is deleted: its unlock wraps, its wrapped member keys and its team states. Its member keys records and grants stay, as part of each team's history, until the teams rotate. The integration refuses to delete an account that is the only owner of a team, for the same reason as above.

### Creating and sharing an item

1. A member starts a draft: the library generates an `itemKey`.
2. Each part is encrypted under it as it is read, buffered or as a stream of chunks, and the integration stores the ciphertext where it wants (D-25, D-27).
3. The member seals the draft with the item's id: the library wraps the `itemKey` under the current team key version, with the list of parts, and stores that key record. The record makes the parts openable.
4. To share by link, the library encodes the `itemKey` for the link fragment. The recipient gets the key record from wherever the integration serves it, and opens that item's parts and nothing else.

### Receiving a submission

1. A member creates an inbox. The library generates the key pair and wraps the private key under the current team key version. The integration puts the public key in the inbox link.
2. On the sender's side, a submission draft generates a `contentKey` and encrypts each part as the integration uploads it. Sealing the draft with the submission's id (chosen by the integration) seals the envelope, the `contentKey` and the list of parts, to the public key from the link. The integration stores the envelope with the parts (D-25).
3. A member's library opens the inbox private key with the team key, opens the envelope the integration gives it, then decrypts each part on demand.

The inbox keeps its key pair after members leave (TH-30, D-20). To end a removed member's access to future submissions, the integration replaces the inbox: a new key pair under the current team key version, and a new link.
