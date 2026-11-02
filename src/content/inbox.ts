// Inboxes (§7.4) and submissions to them (§7.5, §7.6).
import { decodeLinkKey, encodeLinkKey } from "../encoding/link.js";
import { ConvoyError, malformed } from "../errors.js";
import { callPort, type RecordStore } from "../ports.js";
import { createInbox, inboxToJson, openInboxKey, parseInbox, type Inbox } from "../records/inbox.js";
import {
  encryptSubmissionPart,
  encryptSubmissionPartStream,
  openEnvelope,
  openSubmissionPart,
  openSubmissionPartStream,
  parseSubmission,
  sealSubmission,
  submissionToJson,
} from "../records/submission.js";
import type { WireRecord } from "../ports.js";
import type { ContentPorts } from "./context.js";
import { Draft } from "./draft.js";
import { OpenedSubmission } from "./opened.js";
import { commitContent } from "./store.js";

/** Creates and stores an inbox key record; returns the public key for the link's fragment (§7.4). */
export async function storeInbox(
  ports: ContentPorts,
  store: RecordStore,
  input: { teamId: string; inboxId: string; teamKeyVersion: number; createdBy: string },
  teamKey: Uint8Array,
): Promise<{ linkKey: string }> {
  const record = createInbox(ports.suite, { ...input, createdAt: ports.clock.now() }, teamKey);
  await commitContent(store, [{ op: "create", key: { type: "inbox", teamId: input.teamId, inboxId: input.inboxId }, record: inboxToJson(record) }]);
  return { linkKey: encodeLinkKey(record.publicKey) };
}

export async function fetchInbox(store: RecordStore, teamId: string, inboxId: string): Promise<Inbox> {
  const json = await callPort(() => store.get({ type: "inbox", teamId, inboxId }));
  if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
  return parseInbox(json, { teamId, inboxId });
}

/** Seals with the id the integration chose; returns the `submission` record to store with the parts. */
export type SubmissionDraft = Draft<[submissionId: string], WireRecord>;

/**
 * Sender side (§7.5): seals to the public key **from the link**, never one a server
 * offers (SP-14, TH-21). Throws `MALFORMED_RECORD` for a bad or low-order key.
 */
export function newSubmissionDraft(ports: ContentPorts, linkKey: string, teamId: string, inboxId: string): SubmissionDraft {
  const { suite } = ports;
  const publicKey = decodeLinkKey(linkKey);
  if (suite.isLowOrder(publicKey)) throw malformed();
  return new Draft(
    suite,
    (key, index, content) => encryptSubmissionPart(suite, key, index, content),
    (key, index, source, done) => encryptSubmissionPartStream(suite, key, index, source, done),
    async (contentKey, manifest, submissionId) =>
      submissionToJson(sealSubmission(suite, { teamId, inboxId, submissionId }, publicKey, contentKey, ports.clock.now(), manifest)),
  );
}

/** Member side (§7.6): the envelope the integration gives, opened with the inbox key. */
export function openSubmissionRecord(
  ports: ContentPorts,
  inbox: Inbox,
  teamKey: Uint8Array,
  submissionId: string,
  json: unknown,
): OpenedSubmission {
  const { teamId, inboxId } = inbox;
  const record = parseSubmission(json, { teamId, inboxId, submissionId });
  const inboxKey = openInboxKey(inbox, teamKey);
  try {
    const envelope = openEnvelope(record, inboxKey);
    return new OpenedSubmission(
      envelope.createdAt,
      envelope.manifest,
      ports.settings.maxBufferedSize,
      (entry, ciphertext) => openSubmissionPart(record, envelope, entry, ciphertext),
      (entry, source) => openSubmissionPartStream(record, envelope, entry, source),
      () => ports.suite.wipe(envelope.contentKey),
    );
  } finally {
    ports.suite.wipe(inboxKey.secretKey);
  }
}
