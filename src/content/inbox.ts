// Inboxes (§7.4) and submissions to them (§7.5, §7.6).
import { decodeLinkKey, encodeLinkKey } from "../encoding/link.js";
import { ConvoyError, decryptionFailed, malformed } from "../errors.js";
import type { PartKey } from "../ports.js";
import { createInbox, inboxToJson, openInboxKey, parseInbox, type Inbox } from "../records/inbox.js";
import { checkPartCount } from "../records/item.js";
import {
  createSubmission,
  openEnvelope,
  openSubmissionPart,
  parseSubmission,
  submissionToJson,
  type Submission,
} from "../records/submission.js";
import type { ContentPorts, OpenedPart, PartInput } from "./context.js";
import { callPort, commitContent } from "./store.js";

/** Creates and stores an inbox; returns the public key for the link's fragment (§7.4). */
export async function storeInbox(
  ports: ContentPorts,
  input: { teamId: string; inboxId: string; teamKeyVersion: number; createdBy: string },
  teamKey: Uint8Array,
): Promise<{ linkKey: string }> {
  const record = createInbox(ports.suite, { ...input, createdAt: ports.clock.now() }, teamKey);
  await commitContent(ports.store, [{ op: "create", key: { type: "inbox", teamId: input.teamId, inboxId: input.inboxId }, record: inboxToJson(record) }]);
  return { linkKey: encodeLinkKey(record.publicKey) };
}

export async function fetchInbox(ports: ContentPorts, teamId: string, inboxId: string): Promise<Inbox> {
  const json = await callPort(() => ports.store.get({ type: "inbox", teamId, inboxId }));
  if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
  return parseInbox(json, { teamId, inboxId });
}

/**
 * Sender side (§7.5): seals to the public key **from the link**, never one the server
 * offers (SP-14). Throws `MALFORMED_RECORD` for a bad or low-order key.
 */
export async function submit(
  ports: ContentPorts,
  linkKey: string,
  teamId: string,
  inboxId: string,
  parts: readonly PartInput[],
): Promise<{ submissionId: string }> {
  const publicKey = decodeLinkKey(linkKey);
  if (ports.suite.isLowOrder(publicKey)) throw malformed();
  checkPartCount(parts.length);
  const { record, parts: ciphertexts } = createSubmission(ports.suite, { teamId, inboxId }, publicKey, ports.clock.now(), parts);
  const { submissionId } = record;
  await commitContent(ports.store, [
    { op: "create", key: { type: "submission", teamId, inboxId, submissionId }, record: submissionToJson(record) },
    ...ciphertexts.map((bytes, index) => ({ op: "create-part" as const, key: submissionPartKey(record, index), bytes })),
  ]);
  return { submissionId };
}

const submissionPartKey = (r: Submission, index: number): PartKey => ({
  type: "submission-part",
  teamId: r.teamId,
  inboxId: r.inboxId,
  submissionId: r.submissionId,
  index,
});

export interface OpenedSubmission {
  /** Chosen by the sender: informative only, never a trusted time (TH-35). */
  readonly createdAt: number;
  readonly parts: OpenedPart[];
}

/** Member side (§7.6), buffered. */
export async function readSubmission(
  ports: ContentPorts,
  inbox: Inbox,
  teamKey: Uint8Array,
  submissionId: string,
): Promise<OpenedSubmission> {
  const { teamId, inboxId } = inbox;
  const json = await callPort(() => ports.store.get({ type: "submission", teamId, inboxId, submissionId }));
  if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
  const record = parseSubmission(json, { teamId, inboxId, submissionId });
  const inboxKey = openInboxKey(inbox, teamKey);
  try {
    const envelope = openEnvelope(record, inboxKey);
    if (envelope.manifest.some((e) => e.ciphertextSize > ports.settings.maxBufferedSize)) throw malformed();
    const parts: OpenedPart[] = [];
    try {
      for (const entry of envelope.manifest) {
        const ciphertext = await callPort(() => ports.store.getPart(submissionPartKey(record, entry.index)));
        if (!ciphertext) throw decryptionFailed();
        parts.push({ content: openSubmissionPart(record, envelope, entry, ciphertext), meta: entry.meta });
      }
      return { createdAt: envelope.createdAt, parts };
    } catch (error) {
      for (const part of parts) ports.suite.wipe(part.content);
      throw error;
    } finally {
      ports.suite.wipe(envelope.contentKey);
    }
  } finally {
    ports.suite.wipe(inboxKey.secretKey);
  }
}
