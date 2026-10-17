// invite.v1.json: invite records and invite proofs (§4.2, §4.11), with the refusals of SP-24.
import { account, b64u, encode, fixed, hex, label, optionalOf, sodium, wrapWith, wrappedHashOf, wrappedJson, writeVectors } from "./common.mjs";

const TEAM = "team-1";
const T0 = 1_700_000_000;
const alice = account("alice");
const carol = account("carol");
const teamKey = fixed("invite team key", 32);
const joinSecret = fixed("invite join secret", 32);

function inviteRecord({ inviteId, teamKeyVersion = 3, inviteeRef = null, signer = alice }) {
  const context = [["string", TEAM], ["string", inviteId], ["u32", teamKeyVersion], optionalOf(inviteeRef === null ? null : [["string", inviteeRef]])];
  const wrapped = wrapWith(teamKey, fixed(`invite nonce ${inviteId}`, 24), "invite-secret", context, joinSecret);
  const createdAt = T0;
  const message = encode([label("invite"), ...context, ["bytes", hex(wrappedHashOf(wrapped))],
    ["string", signer.accountId], ["bytes", hex(signer.signingPublicKey)], ["u64", createdAt]]);
  return {
    v: 1, suite: "cc1", type: "invite", teamId: TEAM, inviteId, teamKeyVersion, ...(inviteeRef === null ? {} : { inviteeRef }),
    wrappedSecret: wrappedJson(wrapped), signer: { accountId: signer.accountId, signingPublicKey: b64u(signer.signingPublicKey) },
    createdAt, signature: b64u(sodium.crypto_sign_detached(message, signer.signingSecretKey)),
  };
}

// The joiner's keys, as its member-keys record publishes them, and the proof over them.
const recoveryPublicKey = sodium.crypto_sign_seed_keypair(fixed("carol recovery seed", 32)).publicKey;
const keysPayload = (who, accountId = who.accountId) => [["string", TEAM], ["string", accountId], ["u32", 1],
  ["bytes", hex(who.signingPublicKey)], ["bytes", hex(who.encryptionPublicKey)], ["bytes", hex(recoveryPublicKey)]];
const mac = (inviteId, secret, payload) => sodium.crypto_generichash(32, encode([label("invite-proof"), ["string", inviteId], ...payload]), secret);
const mallory = account("mallory");

const proofCases = [
  { name: "valid proof", inviteId: "invite-1", mac: hex(mac("invite-1", joinSecret, keysPayload(carol))), expect: true },
  { name: "another secret", inviteId: "invite-1", mac: hex(mac("invite-1", fixed("other secret", 32), keysPayload(carol))), expect: false },
  { name: "made for another account", inviteId: "invite-1", mac: hex(mac("invite-1", joinSecret, keysPayload(carol, "mallory"))), expect: false },
  { name: "made for other keys", inviteId: "invite-1", mac: hex(mac("invite-1", joinSecret, keysPayload(mallory, "carol"))), expect: false },
  { name: "made for another invite", inviteId: "invite-2", mac: hex(mac("invite-2", joinSecret, keysPayload(carol))), expect: false },
];

const valid = inviteRecord({ inviteId: "invite-1", inviteeRef: "ref-carol" });
writeVectors("invite.v1.json", {
  file: "invite.v1",
  covers: "Protocol §4.11 invite records, §4.2 invite proofs",
  teamId: TEAM,
  teamKey: hex(teamKey),
  joinSecret: hex(joinSecret),
  owner: { accountId: "alice", signingPublicKey: hex(alice.signingPublicKey) },
  joiner: {
    accountId: "carol",
    memberKeysVersion: 1,
    signingPublicKey: hex(carol.signingPublicKey),
    encryptionPublicKey: hex(carol.encryptionPublicKey),
    recoveryPublicKey: hex(recoveryPublicKey),
  },
  invites: { valid, withoutRef: inviteRecord({ inviteId: "invite-2" }) },
  proofCases,
  refused: [
    { name: "signature by another key", record: { ...valid, signer: { accountId: "alice", signingPublicKey: b64u(carol.signingPublicKey) } }, error: "TRUST_FAILURE", reason: "bad_signature" },
    { name: "inviteeRef changed", record: { ...valid, inviteeRef: "ref-mallory" }, error: "TRUST_FAILURE", reason: "bad_signature" },
    { name: "secret of another length", record: { ...valid, wrappedSecret: wrappedJson(wrapWith(teamKey, fixed("short nonce", 24), "invite-secret", [["string", TEAM], ["string", "invite-1"], ["u32", 3], optionalOf([["string", "ref-carol"]])], joinSecret.subarray(0, 16))) }, error: "TRUST_FAILURE", reason: "bad_signature" },
    { name: "unknown field", record: { ...valid, extra: 1 }, error: "MALFORMED_RECORD" },
  ],
});
