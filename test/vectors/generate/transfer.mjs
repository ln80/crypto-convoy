// transfer.v1.json: team key transfers between contexts (§3.8).
import { b64u, encode, fixed, hex, label, listOf, sodium, writeVectors } from "./common.mjs";

const receiverSecret = fixed("receiver secret", 32);
const receiverPublic = sodium.crypto_scalarmult_base(receiverSecret);
const accountId = "alice";
const teamId = "team-1";
const bundle = (version) => ({
  memberKeysVersion: version,
  signingSeed: hex(fixed(`transfer signing seed ${version}`, 32)),
  encryptionSecretKey: hex(fixed(`transfer encryption secret ${version}`, 32)),
  teamStateKey: hex(fixed(`transfer team state key ${version}`, 32)),
});
const bundles = [bundle(2), bundle(1)];
const payload = (list) => listOf(list.map((b) => [["u32", b.memberKeysVersion], ["bytes", b.signingSeed], ["bytes", b.encryptionSecretKey], ["bytes", b.teamStateKey]]));
const transferOf = (list, ctx = [["string", accountId], ["string", teamId]]) =>
  "1" + b64u(sodium.crypto_box_seal(encode([label("team-keys-transfer"), ...ctx, ["bytes", hex(encode([payload(list)]))]]), receiverPublic));

writeVectors("transfer.v1.json", {
  file: "transfer.v1",
  covers: "Protocol §3.8 team key transfer between contexts",
  receiver: { secretKey: hex(receiverSecret), publicKey: hex(receiverPublic), request: "1" + b64u(receiverPublic) },
  context: { accountId, teamId },
  valid: [{ name: "two bundles, newest first", transfer: transferOf(bundles), bundles }],
  refused: [
    { name: "for another team", transfer: transferOf(bundles, [["string", accountId], ["string", "team-2"]]), error: "DECRYPTION_FAILED" },
    { name: "for another account", transfer: transferOf(bundles, [["string", "mallory"], ["string", teamId]]), error: "DECRYPTION_FAILED" },
    { name: "sealed to another receiver", transfer: "1" + b64u(sodium.crypto_box_seal(new Uint8Array(10), sodium.crypto_scalarmult_base(fixed("other receiver", 32)))), error: "DECRYPTION_FAILED" },
    { name: "bundles oldest first", transfer: transferOf([bundle(1), bundle(2)]), error: "MALFORMED_RECORD" },
    { name: "no bundle", transfer: transferOf([]), error: "MALFORMED_RECORD" },
    { name: "prefix 2", transfer: "2" + transferOf(bundles).slice(1), error: "UNSUPPORTED_VERSION" },
  ],
  refusedRequests: [
    { name: "low-order key", request: "1" + b64u(Buffer.alloc(32)), error: "MALFORMED_RECORD" },
    { name: "short key", request: "1" + b64u(receiverPublic.subarray(0, 31)), error: "MALFORMED_RECORD" },
    { name: "prefix 2", request: "2" + b64u(receiverPublic), error: "UNSUPPORTED_VERSION" },
  ],
});
