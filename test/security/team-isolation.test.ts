/**
 * SP-02: A team session only holds its own team's keys.
 * Threats: TH-19.
 */
import { describe, expect, it } from "vitest";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { openPreviousKey, parseTeamKeyVersion } from "../../src/records/team-key-version.js";
import { bundleOf } from "../support/forge.js";
import { team } from "../support/teams.js";

describe("SP-02: a team session holds only its own team's keys", () => {
  it("hands the session one team's keys and no account key or OPRF access", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const session = await alice.vault.openTeam("team-1");
    expect(Object.keys(session.ports).sort()).toEqual(["clock", "localKeys", "settings", "store", "suite"]);
    expect(JSON.stringify(session)).not.toMatch(/key/i);
    const accountKey = alice.vault.requireAccount().key;
    const reachable = [await session.teamKey(1)];
    for (const value of reachable) expect(Buffer.from(value).equals(Buffer.from(accountKey))).toBe(false);
  });

  it("one team's keys open nothing of another team", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const teamB = await alice.vault.createTeam("team-2");
    await teamB.rotate({ keep: [] });
    const teamA = await alice.vault.openTeam("team-1");

    const grantB = parseGrant((await alice.store.list({ type: "grant", teamId: "team-2", accountId: "alice", teamKeyVersion: 2 }))[0], { teamId: "team-2" });
    const keysA = await bundleOf(alice.vault, "team-1");
    expect(() => openGrant(grantB, keysA.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));

    const v2B = parseTeamKeyVersion(await alice.store.get({ type: "team-key-version", teamId: "team-2", version: 2 }), { teamId: "team-2" });
    const keyA = await teamA.teamKey(1);
    expect(() => openPreviousKey(v2B, keyA)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });
});
