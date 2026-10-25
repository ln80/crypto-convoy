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
                  └─────────► recovery signing key (proves re-keys, D-33)
  deviceKey (one per registered device) ───────┘ accountKey (versioned)
                                                    │ wraps
                                                    ▼
TEAM MEMBERSHIP  (one bundle per account and team)
  memberKeys = { signing key (Ed25519), encryption key (X25519), teamStateKey }
     │ public halves published; an owner approves them by rotating the team key
     ▼
TEAM  (one per team)
  teamKey v1 ◄── v2 ◄── v3 …     one signed chain: each version lists its owners
                                 and its roster, links to the previous record's
                                 hash, and wraps the previous key (D-07, D-19, D-34)
     │ each version sealed to its members' encryption keys, in its roster (D-37)
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
| Destruction | Wraps of a retired version stop being served after rotation and are archived for the restore window ([server contract](scope.md#server-contract), rule 7, D-39). |

### `pinKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the `accountKey` for the PIN. |
| Algorithm | Argon2id over the PIN; then a verifiable evaluation by the server, bound to this account (RFC 9497 POPRF, ristretto255-SHA512, D-53); then keyed BLAKE2b combining both. 256-bit result. |
| Generation | Derived each time the user types the PIN. Each derivation costs one rate-limited server evaluation. |
| Storage | Never stored, not even on the device (D-05). |
| Access | Whoever knows the PIN **and** gets a server evaluation for this account. |
| Rotation | On PIN change, with the current PIN or the phrase (D-41): a new wrap replaces the old one. |
| Recovery | Not needed: a lost PIN is replaced through the recovery phrase. |
| Destruction | After a PIN change, the server stops serving the old wrap and archives it for the restore window (rule 7, D-39). |

### `recoveryKey`

| Attribute | Value |
| --- | --- |
| Purpose | Wraps the `accountKey` for the recovery phrase. Used when the PIN is lost or no device is left. |
| Algorithm | 12-word BIP-39 phrase (128 bits of entropy) → BIP-39 seed → keyed BLAKE2b. 256-bit result. |
| Generation | The phrase is generated on the client and shown once. The user keeps it outside the product. |
| Storage | Never stored by the library or the server. |
| Access | Whoever holds the phrase. |
| Rotation | When the user replaces the phrase, with the current phrase or the PIN (D-41). An account key rotation needs the phrase and keeps it. |
| Recovery | None. Losing the phrase and every other unlock method loses the account. |
| Destruction | After a replacement, the server stops serving the old wrap and archives it for the restore window (rule 7, D-39). |

### Recovery signing key

| Attribute | Value |
| --- | --- |
| Purpose | Proves that a member's new keys come from the account's owner: it signs re-keys (D-33, SP-23). The account's offline root of trust. |
| Algorithm | Ed25519. Seed: keyed BLAKE2b-256 of the BIP-39 seed with its own label (§5.2). |
| Generation | Derived from the phrase each time the user types it. |
| Storage | Never stored. Its public half is in every `member-keys` record of the account, and authenticated under the `accountKey` in the recovery wrap, so the vault reads it without the phrase. |
| Access | Whoever holds the phrase. |
| Rotation | With the phrase. Replacing the phrase re-keys every team with the new public key, proven by the old phrase if the user still has it. |
| Recovery | None, as for the phrase. |
| Destruction | Never stored, so nothing to destroy. |

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
| Destruction | Revocation: the server stops serving the device's wrap and archives it (rule 7, D-39). An account key rotation also makes every other device's wrap useless; those devices register again (D-10). |

## Team membership keys

An account has one bundle of member keys per team. Bundles of different teams are independent: holding one says nothing about another (SP-02). The account vault opens the bundle of one team and hands it to that team's session.

### Member signing key

| Attribute | Value |
| --- | --- |
| Purpose | Signs this member's public keys record and, if the member is an owner, owner actions: team key version records, which carry the owner list and the roster. |
| Algorithm | Ed25519. |
| Generation | Random, on the client, when the account joins the team or re-keys. |
| Storage | Private half: in the member keys bundle, wrapped by the `accountKey`. Public half: in the member keys record, published. |
| Access | That team's session. |
| Rotation | On re-key after a suspected leak (SP-12). An owner must approve the new keys, pinned to the version they reviewed; owners' clients approve a re-key proven by the recovery key automatically, except for owners, whose own `reconcile` approves keys it holds (SP-23, D-47). |
| Recovery | Through the `accountKey`. |
| Destruction | The old bundle is deleted once the new keys are approved: at the next open or export of the team, the vault deletes it (protocol §6.8 step 4). |

### Member encryption key

| Attribute | Value |
| --- | --- |
| Purpose | Receives team key versions: owners seal each version to it in the version's roster. |
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
| Purpose | Encrypts this member's copy of the team state on the server: its anchor, the newest team key version record it verified (SP-07). A new device starts from the anchor floor the member keys bundle carries, and follows this anchor when the chain from the floor contains it (D-48, D-52). Only the newest bundle's key counts: a team state under an older bundle's key is absent, and the next advance rewrites it (D-63). |
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
| Storage | Never in clear. Each version is sealed to each member's encryption key in the version record's roster, signed by an owner (D-34, D-37). From version 2 on, each version's record also stores the previous version wrapped under itself (D-07), and every record lists the owners for that version (D-19). |
| Access | Members listed in the roster of that version or a later one. |
| Rotation | After a member is removed (at the next owner `reconcile`, D-31), at every owner change (always, D-13), at a re-key, or after a suspected leak. |
| Recovery | Any member in the current version's roster can open every version. If no member can unlock their account any more, the team's keys are lost. |
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
| **Member keys record** | The member's own signing key | "These are my signing and encryption public keys for this team." The self-signature proves the two keys belong together. It doesn't prove who the member is: an owner approves that by a rotation listing them. |
| **Team key version record** | An owner of the previous version (version 1: its own creator, listed as owner) | "Version n of this team's key exists; its owners are this list; the previous record has this hash; here is version n−1 wrapped under it." The records form one chain that can't be edited, and that chain is also the history of owners (D-19). |
| **Team key version record** (roster) | The same signature | "These accounts, with these keys, receive version n; here it is, sealed to each." |
| **Member keys record**, recovery signature | The account's recovery signing key | "These new keys are mine." A proof the old member keys can't give (SP-23). |

`item` and `inbox` records aren't signed. Their wrap under the team key, with their context, already proves a member created them; signing for authorship is deferred (D-09).

**The owner rule.**
- A roster is valid with its version record; every owner of a version is in its roster.
- A version record n is valid only if its signer is in the owner list of version n−1.

Each owner's signing key must also be the one in that account's published member keys record, so "bob became an owner" really is about Bob's key (SP-15). That's a direct lookup, with nothing to compute. Every owner change (add, remove, replace a key) creates a new version (D-13), so a version's owner list never changes once written, and version numbers are consecutive: nobody chooses them.

A removed owner isn't in the owner list of any later version, so their signatures are refused for all of them. They hold the versions they owned (AS-07), but can't give any version to anyone: a version is only held through its own roster (D-37).

## Who can open what

The blast radius of each leak, and its remedy:

| If this leaks… | …the attacker can open | Remedy |
| --- | --- | --- |
| A PIN (with the user's session) | The `accountKey`, and everything under it | `secureAccount` with a new PIN (SP-11, SP-23; D-36), or just change the PIN if it wasn't used (SP-09) |
| A recovery phrase | Same as a PIN, without needing the server | End the other sessions, then `secureAccount` with a new phrase (SP-11, SP-23; D-45) |
| A device, not used by the attacker | Nothing yet | Revoke the device (SP-10) |
| A device, used by the attacker while unlocked | The `accountKey` and the member keys of every team the device opened | `secureAccount` from another device: rotates the account key and re-keys every team with a recovery proof (SP-11, SP-23; D-36) |
| The `accountKey` | Every member keys bundle of the account, so every team key the account can reach | `secureAccount`: rotation alone doesn't change member keys (SP-11, SP-12, SP-23) |
| A recovery phrase, with the attacker using it | The `accountKey`, and proven re-keys in every team (TH-41) | `secureAccount` with a new phrase; where the thief's keys were approved first, an owner approves the user's keys by hand. After a takeover, a support restore first (TH-48) |
| One team's member keys | Every version of that team's key given to the member, and every earlier version | Re-key in that team, approved by an owner, then rotate the team key (SP-12) |
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
3. Register this device: generate `deviceKey`, keep it locally, store the device wrap.
4. Set up recovery (D-35): the vault generates a phrase and keeps it in memory; the user enters it back, with the current PIN (D-61); only then derive `recoveryKey` and the recovery signing key, and store the recovery wrap with the recovery public key. Until this is done, the account can't create or join a team.

### Adding a device

1. On the new device, the user enters the PIN (or the recovery phrase), which opens the `accountKey`.
2. The device registers: a new `deviceKey` and a new device wrap.

Other devices are not affected.

### Losing the PIN

1. The user enters the recovery phrase, which opens the `accountKey`.
2. The user chooses a new PIN. The new PIN wrap replaces the old one.

### Changing the PIN

1. Open the `accountKey` with any unlock method, and enter the current PIN (one server evaluation) or the recovery phrase (D-41).
2. Store the new wrap in place of the old one (`replace`). The server archives the old one without serving it, so the old credential stops working at once (SP-09, D-39).

A copy of the old wrap taken before the replacement, or restored from the archive, still opens the current `accountKey` with the old credential. If that's a concern, also rotate the account key.

### Replacing the recovery phrase

1. Open the `accountKey`, enter the current phrase or the current PIN (D-41), set up a new phrase as at account setup (two steps), and store its wrap in place of the old one (SP-09).
2. Re-key every team (§6.8): the new member keys carry the new recovery public key.
   - The user still has the old phrase: the re-keys are signed by the old recovery key, and owners' `reconcile` approves them (SP-23); in teams where the account is an owner, its own `reconcile` does (D-47).
   - The old phrase is lost, and the user entered the PIN: the re-keys carry no proof, and an owner approves each by hand. If the old phrase may have leaked, secure the account with the new one next.

If the phrase may have leaked and the user still has it, `secureAccount` with a new phrase does the replacement, the rotation and proven re-keys in one pass (D-45).

### Losing a device (D-21, D-36)

Two cases:

- **Not used by anyone** (locked, wiped, or nobody opened the app). From another device, or after recovery, revoke it. The server stops serving its wrap, and the device can't unlock again (SP-10). Nothing else is needed.
- **Possibly used while unlocked.** Assume the attacker copied the `accountKey` and the member keys of every team the device opened. Revocation alone doesn't evict them, because every new team key version is still sealed to those member keys. The integration ends the account's other sign-in sessions first (D-43). From another device, the user runs `secureAccount` with the recovery phrase and a new PIN, or the phrase alone when the PIN budget is spent (D-40, TH-44). The stolen device can't take this remedy away first: it can't change the account's credentials (D-41).
  1. the account key is rotated (SP-11), which cuts every other device (D-10);
  2. every team is re-keyed, each re-key signed by the recovery key (SP-23);
  3. each team's owners approve the new keys at their next `reconcile`, by rotating; where the user is an owner, their own next `reconcile` on this device approves them (D-47).

  After that, the copied keys open nothing written afterwards. A team that failed to re-key is reported and retried.

### Rotating the account key (D-10)

1. Open the current `accountKey`.
2. The user enters the recovery phrase (D-41), and optionally a new PIN (one server evaluation, D-40).
3. Generate the next `accountKey` version and re-wrap every member keys bundle under it.
4. Store the current-device wrap, the recovery wrap, and the new PIN wrap if a PIN was entered; switch the account to the new version in one atomic step. Without a PIN, the account has none until the user sets one (D-40).
5. The server stops serving every record of the old version and archives it (rule 7, D-42). Other devices register again after a PIN or phrase unlock.

### Restoring an account (D-42)

When someone took over the account with a credential (they replaced the phrase or the PIN, perhaps rotated), the integration's support process restores it:

1. Support restores the account key version from before the takeover: it becomes current again, the thief's later versions are archived, and the user's wraps and member keys wraps of that version are served again. Within one version, support restores the single records the thief replaced.
2. Support ends the account's sign-in sessions; the user unlocks with their own PIN or phrase and secures the account (§5.11): with a new PIN, and a new phrase if the thief knew the restored one (D-45). Securing alone keeps the restored phrase, which the thief could use again.
3. Devices that accepted the thief's version refuse the older one (`rollback`): they are reset and register again. In teams where an owner approved the thief's keys, the user's re-key needs an owner's approval.

Member keys don't change, so teams see nothing. The old `accountKey` only opens records that the server no longer serves (SP-11). For the same reason, rotation alone doesn't end team access for someone who already copied a member keys bundle; that takes a re-key in each team (`secureAccount` does both).

### Creating a team

1. The creator's vault generates their member keys for the team (recovery must be set up).
2. They generate `teamKey` version 1 and its record: owners and roster are the creator.
3. The record and the member keys are stored in one atomic batch, so a team never exists half set up. The bundle's anchor floor is version 1 (D-48).

### Inviting and joining a team

1. An owner puts the team's anchor (`team.inviteAnchor()`) in the invite link, which the integration delivers.
2. The joining account's vault verifies the chain the server serves, from the anchor in the link (or from version 1 without one), then generates member keys for the team, stores the bundle wrapped by its `accountKey` with the chain's tip as its floor (D-48, D-50), and publishes its member keys record. (Anything that wraps member keys runs in the vault.) Every device, in the vault's context or a receiving one (§3.8), starts from that floor when it has no newer anchor. When the link reached the joiner outside the server, a forged team is refused; otherwise the join trusts the chain served (TH-04).
3. An owner checks the request is genuine (AS-06) and approves those keys: a rotation whose roster adds the member (D-37). Several approvals can share one rotation.
4. The new member opens the current version from its roster entry, and every earlier version by walking the chain (D-07).

Until that rotation, the member is *pending*. `reconcile` never approves a first join: it always needs a human.

### Removing a member

1. The integration removes the member's access on its server, and from the active list it gives owners.
2. At the next owner session, `reconcile` rotates the team key without them (D-31).

The removed member keeps every key they had (AS-07): every version up to the rotation, and their items and inboxes. They can't open the new version, or items and inboxes created with it (SP-06), unless a later rotation lists them again; the chain then opens the gap too. Inboxes created earlier stay open to them, if they obtain the ciphertexts, until replaced (TH-30).

### Rotating the team key

1. An owner of the current version n opens it.
2. Recipients: the accounts the owner keeps (an explicit list, normally the active members) that hold version n, in its roster. Anyone left off the list gets nothing, so forgetting someone costs access instead of leaking it. Each recipient receives one set of keys: its newest keys if this rotation approves them, otherwise the keys it holds. The rotation can also add accounts whose keys the owner approved: that is how members join.
3. Generate version n+1. Its record lists the owners (unchanged, unless this rotation changes them), the roster (each recipient's keys, as a hash, and version n+1 sealed to them), links to version n's record, and wraps version n under the new key.
4. Store the record. One write: a rotation can't be half done (D-34).

### Changing the owners: add, remove, replace a key (D-13)

Every owner change is a rotation whose new version carries the new owner list. The version record carries the owner list and the roster in one write, so the change is never half applied.

- **Adding an owner:** the new owner must already be a member holding the current version.
- **Removing an owner:** members whose current access was given by the removed owner are shown to the rotating owner as a warning before they receive the new version. It's a warning, not a guarantee: a later rotation by another owner hides that origin.
- After removal, the removed owner's signatures are refused for every later version.

### An owner loses their credentials

1. Another owner removes them from the owner list (previous scenario).
2. The person recovers their account, or sets up a new one, and joins again with new member keys.
3. An owner approves their keys (a rotation) and, if wanted, adds them back as an owner.

A team with a single owner can't do this. Nobody can manage the team any more (TH-18).

### Re-keying after a suspected leak of member keys

1. The member's vault generates new member keys for the team and publishes them, signed by the recovery key if the user enters the phrase. The new bundle's anchor floor is the newest version of a chain containing the current floor and the vault's own anchor, or of one from an anchor an owner gives (D-54). Until step 2, the member keeps reading with the old keys.
2. An owner approves the new keys by rotating the team key: the new version is sealed to them, and the old keys receive nothing. The approval names the keys the owner reviewed, by version and keys hash (SP-12, D-55).
   - Proven by the recovery key, for a member who isn't an owner: owners' `reconcile` approves it (SP-23).
   - Otherwise: an owner checks the request is genuine first (AS-06). The old keys can't vouch for the new ones, since the attacker may hold them (D-38).
3. If the member is an owner, the same rotation replaces their signing key in the owner list.

One rotation does it all: the chain gives the new keys every earlier version, and a rotation only ever carries one set of keys per account.

### Leaving a team

1. The member's vault deletes its wrapped member keys and its team state for the team.
2. The remaining owners' `reconcile` rotates the team key without the member, once the integration drops them from the active list.

A listed owner can't leave: the library refuses (`LAST_OWNER`). The owner steps down first, through an owner change (`setOwners` without it), which always keeps one owner, so the only owner can never leave. Otherwise the team would freeze (TH-18, D-65).

### Deleting an account

Every record private to the account is deleted: its unlock wraps, its wrapped member keys and its team states. Its member keys records stay, as part of each team's history, and its roster entries remain in the versions it held. The integration refuses to delete an account that is the only owner of a team, for the same reason as above.

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
