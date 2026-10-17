// team-key.v1.json: member keys, team key version records and their chain, grants (§4.2, §4.5, §4.6),
// with the attack cases of SP-04 and SP-05, and strict Ed25519 edge cases (§2).
import {
  account, b64u, blake, encode, fixed, hex, label, listOf, optionalOf, sodium,
  wrapWith, wrappedHashOf, wrappedJson, writeVectors,
} from "./common.mjs";

const TEAM = "team-1";
const T0 = 1_700_000_000;
const [alice, bob, carol, mallory] = ["alice", "bob", "carol", "mallory"].map(account);
const teamKeys = [null, fixed("team key 1", 32), fixed("team key 2", 32), fixed("team key 3", 32), fixed("team key 4", 32)];
const sign = (who, message) => sodium.crypto_sign_detached(message, who.signingSecretKey);

function memberKeys(who, version = 1) {
  const createdAt = T0;
  const message = encode([label("member-keys"), ["string", TEAM], ["string", who.accountId], ["u32", version],
    ["bytes", hex(who.signingPublicKey)], ["bytes", hex(who.encryptionPublicKey)], ["u64", createdAt]]);
  return {
    v: 1, suite: "cc1", type: "member-keys", teamId: TEAM, accountId: who.accountId, memberKeysVersion: version,
    signingPublicKey: b64u(who.signingPublicKey), encryptionPublicKey: b64u(who.encryptionPublicKey),
    createdAt, signature: b64u(sign(who, message)),
  };
}

const ownerRef = (who, key = who.signingPublicKey) => ({ accountId: who.accountId, signingPublicKey: key });

/** A version record; `override` changes inputs to build the attack cases. */
function versionRecord({ version, prevHash, owners, signer, signerKey = signer, createdAt = T0 + version, linkKey = teamKeys[version] }) {
  const wrapped = version === 1 ? null
    : wrapWith(linkKey, fixed(`link nonce ${version}`, 24), "team-key-link", [["string", TEAM], ["u32", version]], teamKeys[version - 1]);
  const signerRef = ownerRef(signer, signerKey.signingPublicKey);
  const payload = encode([
    label("team-key-version"), ["string", TEAM], ["u32", version], ["bytes", hex(prevHash)],
    listOf(owners.map((o) => [["string", o.accountId], ["bytes", hex(o.signingPublicKey)]])),
    optionalOf(wrapped ? [["bytes", hex(wrappedHashOf(wrapped))]] : null),
    ["string", signerRef.accountId], ["bytes", hex(signerRef.signingPublicKey)], ["u64", createdAt],
  ]);
  const signature = sign(signerKey, payload);
  return {
    record: {
      v: 1, suite: "cc1", type: "team-key-version", teamId: TEAM, version, prevHash: b64u(prevHash),
      owners: owners.map((o) => ({ accountId: o.accountId, signingPublicKey: b64u(o.signingPublicKey) })),
      wrappedPreviousKey: wrapped ? wrappedJson(wrapped) : null,
      signer: { accountId: signerRef.accountId, signingPublicKey: b64u(signerRef.signingPublicKey) },
      createdAt, signature: b64u(signature),
    },
    payload: hex(payload),
    recordHash: hex(blake(payload)),
  };
}

function grantRecord({ member, teamKeyVersion, signer, memberKeysVersion = 1, teamKey = teamKeys[teamKeyVersion] }) {
  const sealContext = [["string", TEAM], ["string", member.accountId], ["u32", memberKeysVersion], ["u32", teamKeyVersion]];
  const sealed = sodium.crypto_box_seal(encode([label("grant-seal"), ...sealContext, ["bytes", hex(teamKey)]]), member.encryptionPublicKey);
  const createdAt = T0 + 100 + teamKeyVersion;
  const message = encode([label("grant"), ["string", TEAM], ["string", member.accountId], ["u32", memberKeysVersion],
    ["bytes", hex(member.signingPublicKey)], ["bytes", hex(member.encryptionPublicKey)], ["u32", teamKeyVersion],
    ["bytes", hex(blake(sealed))], ["string", signer.accountId], ["bytes", hex(signer.signingPublicKey)], ["u64", createdAt]]);
  return {
    v: 1, suite: "cc1", type: "grant", teamId: TEAM, accountId: member.accountId, memberKeysVersion,
    memberSigningPublicKey: b64u(member.signingPublicKey), memberEncryptionPublicKey: b64u(member.encryptionPublicKey),
    teamKeyVersion, sealedTeamKey: b64u(sealed),
    signer: { accountId: signer.accountId, signingPublicKey: b64u(signer.signingPublicKey) },
    createdAt, signature: b64u(sign(signer, message)),
  };
}

const zero = new Uint8Array(32);
const fromHex = (text) => new Uint8Array(Buffer.from(text, "hex"));
// The honest chain: v1 owners [alice]; v2 adds bob (signed by alice); v3 removes alice (signed by bob).
const v1 = versionRecord({ version: 1, prevHash: zero, owners: [ownerRef(alice)], signer: alice });
const v2 = versionRecord({ version: 2, prevHash: fromHex(v1.recordHash), owners: [ownerRef(alice), ownerRef(bob)], signer: alice });
const v3 = versionRecord({ version: 3, prevHash: fromHex(v2.recordHash), owners: [ownerRef(bob)], signer: bob });

const members = [alice, bob, carol].map((who) => memberKeys(who));
const grants = {
  aliceV1: grantRecord({ member: alice, teamKeyVersion: 1, signer: alice }),
  bobV2: grantRecord({ member: bob, teamKeyVersion: 2, signer: alice }),
  carolV3: grantRecord({ member: carol, teamKeyVersion: 3, signer: bob }),
};

// Strict Ed25519 cases on v1's signature (§2).
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const le = (n) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const leValue = (bytes) => [...bytes].reverse().reduce((n, b) => (n << 8n) | BigInt(b), 0n);
const sig1 = Buffer.from(v1.record.signature, "base64url");
const nonCanonicalS = Buffer.concat([sig1.subarray(0, 32), le(leValue(sig1.subarray(32)) + L)]);
const smallOrderR = Buffer.concat([Buffer.alloc(32), sig1.subarray(32)]);
const smallOrderSigner = { ...v1.record, signer: { accountId: "alice", signingPublicKey: b64u(Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex")) } };

const unsorted = { ...v2.record, owners: [...v2.record.owners].reverse() };
const duplicate = { ...v2.record, owners: [v2.record.owners[0], v2.record.owners[0]] };

const chainCases = [
  { name: "honest chain from first contact", chain: [1, 2, 3], anchors: [], expect: { current: 3 } },
  { name: "honest chain from an anchor at v2", chain: [2, 3], anchors: [[2, v2.recordHash]], expect: { current: 3 } },
  { name: "gap: v2 missing", chain: [1, 3], anchors: [], expect: { error: "TRUST_FAILURE", reason: "chain_conflict" } },
  { name: "rollback: chain stops before the anchor", chain: [1, 2], anchors: [[3, v3.recordHash]], expect: { error: "TRUST_FAILURE", reason: "rollback" } },
  { name: "fork: another v2 than the anchored one", chain: [1, "forkV2"], anchors: [[2, v2.recordHash]], expect: { error: "TRUST_FAILURE", reason: "chain_conflict" } },
  { name: "wrong prevHash", chain: [1, "badPrevV2"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "chain_conflict" } },
  { name: "v2 signed by a non-owner", chain: [1, "carolSignsV2"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "v4 signed by the removed owner", chain: [1, 2, 3, "aliceSignsV4"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "signer with an owner's id but another key", chain: [1, "aliceOtherKeyV2"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "v1 signer not in its own owners", chain: ["malloryV1"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "owner key not matching member keys", chain: [1, "bobWrongKeyV2"], anchors: [], expect: { error: "TRUST_FAILURE", reason: "key_mismatch" } },
];

const bobOtherKey = account("bob-other");
const variants = {
  forkV2: versionRecord({ version: 2, prevHash: fromHex(v1.recordHash), owners: [ownerRef(alice), ownerRef(mallory)], signer: alice }).record,
  badPrevV2: versionRecord({ version: 2, prevHash: fixed("not the hash", 32), owners: [ownerRef(alice), ownerRef(bob)], signer: alice }).record,
  carolSignsV2: versionRecord({ version: 2, prevHash: fromHex(v1.recordHash), owners: [ownerRef(alice), ownerRef(carol)], signer: carol }).record,
  aliceSignsV4: versionRecord({ version: 4, prevHash: fromHex(v3.recordHash), owners: [ownerRef(alice)], signer: alice }).record,
  malloryV1: versionRecord({ version: 1, prevHash: zero, owners: [ownerRef(alice)], signer: mallory }).record,
  bobWrongKeyV2: versionRecord({ version: 2, prevHash: fromHex(v1.recordHash), owners: [ownerRef(alice), ownerRef(bob, bobOtherKey.signingPublicKey)], signer: alice }).record,
};
// aliceOtherKeyV2: signer claims accountId "alice" with mallory's key; the signature is mallory's.
variants.aliceOtherKeyV2 = (() => {
  const payloadSigner = { accountId: "alice", signingPublicKey: mallory.signingPublicKey, signingSecretKey: mallory.signingSecretKey };
  return versionRecord({ version: 2, prevHash: fromHex(v1.recordHash), owners: [ownerRef(alice), ownerRef(bob)], signer: payloadSigner }).record;
})();

const grantCases = [
  { name: "grant of v1 to alice by alice", grant: grants.aliceV1, member: "alice", expect: { teamKey: hex(teamKeys[1]) } },
  { name: "grant of v2 to bob by alice", grant: grants.bobV2, member: "bob", expect: { teamKey: hex(teamKeys[2]) } },
  { name: "grant of v3 to carol by bob", grant: grants.carolV3, member: "carol", expect: { teamKey: hex(teamKeys[3]) } },
  { name: "grant of v3 signed by the removed owner", grant: grantRecord({ member: carol, teamKeyVersion: 3, signer: alice }), member: "carol", expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "grant of v2 signed by a non-owner", grant: grantRecord({ member: carol, teamKeyVersion: 2, signer: carol }), member: "carol", expect: { error: "TRUST_FAILURE", reason: "not_an_owner" } },
  { name: "grant naming other member keys", grant: grantRecord({ member: { ...carol, encryptionPublicKey: mallory.encryptionPublicKey, encryptionSecretKey: mallory.encryptionSecretKey }, teamKeyVersion: 3, signer: bob }), member: "carol", expect: { error: "TRUST_FAILURE", reason: "key_mismatch" } },
];

const recordCases = [
  { name: "non-canonical S", record: { ...v1.record, signature: b64u(nonCanonicalS) }, expect: { error: "TRUST_FAILURE", reason: "bad_signature" } },
  { name: "small-order R", record: { ...v1.record, signature: b64u(smallOrderR) }, expect: { error: "TRUST_FAILURE", reason: "bad_signature" } },
  { name: "small-order signer key", record: smallOrderSigner, expect: { error: "MALFORMED_RECORD" } },
  { name: "owners not sorted", record: unsorted, expect: { error: "MALFORMED_RECORD" } },
  { name: "duplicate owner", record: duplicate, expect: { error: "MALFORMED_RECORD" } },
  { name: "no owners", record: { ...v1.record, owners: [] }, expect: { error: "MALFORMED_RECORD" } },
  { name: "v1 with a previous key", record: { ...v1.record, wrappedPreviousKey: v2.record.wrappedPreviousKey }, expect: { error: "MALFORMED_RECORD" } },
  { name: "v2 without a previous key", record: { ...v2.record, wrappedPreviousKey: null }, expect: { error: "MALFORMED_RECORD" } },
  { name: "createdAt changed", record: { ...v2.record, createdAt: v2.record.createdAt + 1 }, expect: { error: "TRUST_FAILURE", reason: "bad_signature" } },
  { name: "unknown field", record: { ...v1.record, extra: 1 }, expect: { error: "MALFORMED_RECORD" } },
  { name: "unknown suite", record: { ...v1.record, suite: "cc9" }, expect: { error: "UNSUPPORTED_VERSION" } },
  { name: "unknown version", record: { ...v1.record, v: 2 }, expect: { error: "UNSUPPORTED_VERSION" } },
];

writeVectors("team-key.v1.json", {
  file: "team-key.v1",
  covers: "Protocol §4.2 member keys, §4.5 team key versions and chain, §4.6 grants, §2 strict Ed25519",
  teamId: TEAM,
  accounts: Object.fromEntries([alice, bob, carol, mallory].map((a) => [a.accountId, {
    signingSeed: hex(fixed(`${a.accountId} signing seed`, 32)),
    encryptionSecretKey: hex(a.encryptionSecretKey),
  }])),
  teamKeys: Object.fromEntries(teamKeys.slice(1).map((k, i) => [i + 1, hex(k)])),
  memberKeys: members,
  versions: { 1: v1, 2: v2, 3: v3 },
  variants,
  chainCases,
  grantCases,
  recordCases,
});
