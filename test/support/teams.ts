// Team scenarios on top of fixtures: owners, members, grants.
import type { AccountOverview } from "../../src/team/membership.js";
import type { TeamOwner } from "../../src/team/owner.js";
import { world } from "./fixtures.js";

/** alice creates team-1; each other name joins and is granted by alice. */
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
    const request = await requestOf(aliceTeam.owner(), name);
    await aliceTeam.owner().grant(request.keys!);
    members[name] = member;
  }
  return { w, members, aliceTeam };
}

/** One account as an owner's overview shows it (§6.9). */
export async function requestOf(owner: TeamOwner, accountId: string): Promise<AccountOverview> {
  return (await owner.overview([accountId])).accounts.find((a) => a.accountId === accountId)!;
}
