// Team scenarios on top of fixtures: owners, members, grants.
import type { AccountOverview } from "../../src/team/membership.js";
import type { TeamOwner } from "../../src/team/owner.js";
import { world } from "./fixtures.js";

/**
 * alice creates team-1 (version 1); the other names join and alice approves them all in one
 * rotation (version 2, D-37). Without others, the team stays at version 1.
 */
export async function team(...others: string[]) {
  const w = world();
  const alice = await w.account("alice");
  await alice.vault.createTeam("team-1");
  const aliceTeam = await alice.vault.openTeam("team-1");
  const members: Record<string, Awaited<ReturnType<typeof w.account>>> = { alice };
  for (const name of others) {
    const member = await w.account(name);
    await member.vault.joinTeam("team-1");
    // The joiner's first open: first contact, anchored from here on (§6.1).
    (await member.vault.openTeam("team-1")).close();
    members[name] = member;
  }
  if (others.length > 0) {
    const { accounts } = await aliceTeam.owner().overview(others);
    await aliceTeam.owner().approve(others.map((name) => accounts.find((a) => a.accountId === name)!.keys!));
  }
  return { w, members, aliceTeam };
}

/** One account as an owner's overview shows it (§6.9). */
export async function requestOf(owner: TeamOwner, accountId: string): Promise<AccountOverview> {
  return (await owner.overview([accountId])).accounts.find((a) => a.accountId === accountId)!;
}
