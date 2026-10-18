// One parse call per record type, with the context the samples were made for.
import { parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { parseInbox } from "../../src/records/inbox.js";
import { parseItem } from "../../src/records/item.js";
import { parseMemberKeys } from "../../src/records/member-keys.js";
import { parseMemberKeysWrap } from "../../src/records/member-keys-wrap.js";
import { parseSubmission } from "../../src/records/submission.js";
import { parseTeamKeyVersion } from "../../src/records/team-key-version.js";
import { parseTeamState } from "../../src/records/team-state.js";
import type { SampleType } from "./records.js";

export function parsers(submissionId: string): Record<SampleType, (json: unknown) => unknown> {
  return {
    "account-key-wrap": (j) => parseAccountKeyWrap(j, { accountId: "alice", accountKeyVersion: 1, method: "recovery" }),
    "member-keys": (j) => parseMemberKeys(j, { teamId: "team-1", accountId: "alice" }),
    "member-keys-wrap": (j) => parseMemberKeysWrap(j, { accountId: "alice", teamId: "team-1", accountKeyVersion: 1 }),
    "team-state": (j) => parseTeamState(j, { accountId: "alice", teamId: "team-1" }),
    "team-key-version": (j) => parseTeamKeyVersion(j, { teamId: "team-1" }),
    item: (j) => parseItem(j, { teamId: "team-1", itemId: "item-1" }),
    inbox: (j) => parseInbox(j, { teamId: "team-1", inboxId: "inbox-1" }),
    submission: (j) => parseSubmission(j, { teamId: "team-1", inboxId: "inbox-1", submissionId }),
  };
}
