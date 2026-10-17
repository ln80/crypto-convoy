// Team scenarios on top of fixtures: owners, members, grants.
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
    const request = await aliceTeam.memberRequest(name);
    await aliceTeam.grant(name, request.memberKeysVersion);
    members[name] = member;
  }
  return { w, members, aliceTeam };
}
