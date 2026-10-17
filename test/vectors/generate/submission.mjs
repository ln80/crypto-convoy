// submission.v1.json: envelope and parts (§4.10).
import { b64u, blake, encode, fixed, hex, label, listOf, sodium, writeVectors } from "./common.mjs";

const TEAM = "team-1";
const INBOX = "inbox-1";
// Chosen by the integration, for example its server's id for the submission (§1).
const SUBMISSION = "submission-42";
const inboxSecret = fixed("inbox secret", 32);
const inboxPublic = sodium.crypto_scalarmult_base(inboxSecret);
const contentKey = fixed("content key", 32);
const createdAt = 1_700_000_900;
const context = [["string", TEAM], ["string", INBOX], ["string", SUBMISSION]];

const plaintexts = [new TextEncoder().encode("a message from outside"), fixed("attachment", 64)];
const parts = plaintexts.map((plaintext, index) => {
  const ad = encode([label("submission-part"), ["u32", index]]);
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(contentKey);
  return new Uint8Array(Buffer.concat([header, sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext, ad, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)]));
});
const body = encode([["bytes", hex(contentKey)], ["u64", createdAt],
  listOf(parts.map((ct, index) => [["u32", index], ["u64", ct.length], ["bytes", hex(blake(ct))], ["bytes", ""]]))]);
const sealedEnvelope = sodium.crypto_box_seal(encode([label("submission"), ...context, ["bytes", hex(body)]]), inboxPublic);

const record = { v: 1, suite: "cc1", type: "submission", teamId: TEAM, inboxId: INBOX, submissionId: SUBMISSION, sealedEnvelope: b64u(sealedEnvelope) };
const otherInbox = sodium.crypto_box_seal(encode([label("submission"), ["string", TEAM], ["string", "inbox-2"], ["string", SUBMISSION], ["bytes", hex(body)]]), inboxPublic);

writeVectors("submission.v1.json", {
  file: "submission.v1",
  covers: "Protocol §4.10 submission, D-14 content key",
  inbox: { secretKey: hex(inboxSecret), publicKey: hex(inboxPublic) },
  contentKey: hex(contentKey),
  createdAt,
  record,
  parts: parts.map((ct, i) => ({ ciphertext: hex(ct), plaintext: hex(plaintexts[i]) })),
  tampered: [
    { name: "envelope sealed for another inbox", record: { ...record, sealedEnvelope: b64u(otherInbox) }, error: "DECRYPTION_FAILED" },
    { name: "envelope served under another submission id", record: { ...record, submissionId: "submission-43" }, error: "DECRYPTION_FAILED" },
    { name: "empty submission id", record: { ...record, submissionId: "" }, error: "MALFORMED_RECORD" },
  ],
});
