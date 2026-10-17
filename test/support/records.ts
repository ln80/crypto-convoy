// Valid records of every type, built with the library, for round-trip, downgrade and fuzz tests.
import { accountKeyWrapToJson, createAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { createGrant, grantToJson } from "../../src/records/grant.js";
import { createInbox, inboxToJson } from "../../src/records/inbox.js";
import { createItem, itemToJson } from "../../src/records/item.js";
import { createInvite, inviteToJson } from "../../src/records/invite.js";
import { createMemberKeys, keysHash, memberKeysToJson } from "../../src/records/member-keys.js";
import { bundleKeyPairs, createMemberKeysWrap, generateBundle, memberKeysWrapToJson } from "../../src/records/member-keys-wrap.js";
import { createSubmission, submissionToJson } from "../../src/records/submission.js";
import { createTeamKeyVersion, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import { createTeamState, teamStateToJson } from "../../src/records/team-state.js";
import { cc1 } from "../../src/suites/cc1/index.js";

export function sampleRecords() {
  const suite = cc1;
  const accountKey = suite.randomBytes(32);
  const teamKey = suite.randomBytes(32);
  const bundle = generateBundle(suite);
  const pairs = bundleKeyPairs(suite, bundle);
  const signer = { accountId: "alice", signingPublicKey: pairs.signing.publicKey };
  const recovery = suite.signingKeyPair(suite.randomBytes(32));
  const memberKeys = createMemberKeys(
    suite,
    {
      teamId: "team-1", accountId: "alice", memberKeysVersion: 1, signingPublicKey: pairs.signing.publicKey,
      encryptionPublicKey: pairs.encryption.publicKey, recoveryPublicKey: recovery.publicKey, createdAt: 1,
    },
    pairs.signing.secretKey,
    { recoverySigningSecretKey: recovery.secretKey, invite: { inviteId: "invite-1", secret: suite.randomBytes(32) } },
  );
  const hash = keysHash(suite, memberKeys);
  const version = createTeamKeyVersion(suite, {
    teamId: "team-1", version: 1, prevHash: new Uint8Array(32), owners: [signer], createdAt: 1,
    roster: [{ accountId: "alice", memberKeysVersion: 1, keysHash: hash, encryptionPublicKey: pairs.encryption.publicKey }],
    signer, signerSecretKey: pairs.signing.secretKey, teamKey,
  });
  const grant = createGrant(suite, {
    teamId: "team-1", accountId: "alice", memberKeysVersion: 1, teamKeyVersion: 1, keysHash: hash,
    encryptionPublicKey: pairs.encryption.publicKey, inviteId: "invite-1",
    teamKey, signer, signerSecretKey: pairs.signing.secretKey, createdAt: 1,
  });
  const invite = createInvite(suite, {
    teamId: "team-1", inviteId: "invite-1", teamKeyVersion: 1, inviteeRef: "ref", teamKey, secret: suite.randomBytes(32),
    signer, signerSecretKey: pairs.signing.secretKey, createdAt: 1,
  });
  const item = createItem(suite, { teamId: "team-1", itemId: "item-1", teamKeyVersion: 1, createdBy: "alice", createdAt: 1 }, teamKey, [
    { content: new TextEncoder().encode("hi"), meta: new Uint8Array([1]) },
  ]);
  const inbox = createInbox(suite, { teamId: "team-1", inboxId: "inbox-1", teamKeyVersion: 1, createdBy: "alice", createdAt: 1 }, teamKey);
  const submission = createSubmission(suite, { teamId: "team-1", inboxId: "inbox-1", submissionId: "submission-1" }, inbox.publicKey, 1, [
    { content: new TextEncoder().encode("hello") },
  ]);
  return {
    secrets: { accountKey, teamKey, bundle, pairs, methodKey: accountKey.slice().reverse() },
    records: {
      "account-key-wrap": accountKeyWrapToJson(
        createAccountKeyWrap(suite, { accountId: "alice", accountKeyVersion: 1, method: "recovery" }, accountKey.slice().reverse(), accountKey, recovery.publicKey),
      ),
      "member-keys": memberKeysToJson(memberKeys),
      "member-keys-wrap": memberKeysWrapToJson(
        createMemberKeysWrap(suite, { accountId: "alice", teamId: "team-1", memberKeysVersion: 1, accountKeyVersion: 1 }, accountKey, bundle),
      ),
      "team-state": teamStateToJson(
        createTeamState(suite, { accountId: "alice", teamId: "team-1" }, 1, bundle.teamStateKey, { version: 1, hash: new Uint8Array(32) }),
      ),
      "team-key-version": teamKeyVersionToJson(version),
      grant: grantToJson(grant),
      invite: inviteToJson(invite),
      item: itemToJson(item.record),
      inbox: inboxToJson(inbox),
      submission: submissionToJson(submission.record),
    },
    parts: { item: item.parts, submission: submission.parts },
    submissionId: submission.record.submissionId,
  };
}

export type SampleType = keyof ReturnType<typeof sampleRecords>["records"];
