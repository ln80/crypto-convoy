/** Vault operations take and return plain data, so an integration can carry them between contexts (§12). */
import { describe, expect, it } from "vitest";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { world } from "../support/fixtures.js";

describe("vault results are structured-cloneable", () => {
  it("setup, status, devices, exports and rotation", async () => {
    const w = world();
    const alice = await w.device("alice");
    const results: unknown[] = [await alice.vault.status(), await alice.vault.setup("1234"), await alice.vault.status()];
    const begun = alice.vault.beginRecoverySetup();
    results.push(begun, await alice.vault.confirmRecoveryPhrase(begun.recoveryPhrase, { currentPin: "1234" }), await alice.vault.warnings());
    await alice.vault.createTeam("team-1");
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    results.push(
      receiver.request,
      await alice.vault.exportTeamKeys("team-1", receiver.request),
      await alice.vault.listDevices(),
    );
    const next = alice.vault.beginRecoverySetup();
    results.push(
      await alice.vault.confirmRecoveryPhrase(next.recoveryPhrase, { currentPhrase: begun.recoveryPhrase }),
      await alice.vault.secureAccount({ phrase: next.recoveryPhrase, newPin: "4321" }),
      await alice.vault.rotate({ phrase: next.recoveryPhrase, newPin: "4321" }),
    );
    for (const value of results) expect(structuredClone(value)).toEqual(value);
  });
});
