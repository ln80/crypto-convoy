/**
 * SP-01: The server never holds a key that opens items.
 * Threats: TH-01, TH-29.
 */
import { describe, expect, it } from "vitest";
import { submit } from "../../src/content/inbox.js";
import { decodeLinkKey } from "../../src/encoding/link.js";
import { bundleOf } from "../support/forge.js";
import { outsider } from "../support/link-client.js";
import { team } from "../support/teams.js";

const text = (s: string) => new TextEncoder().encode(s);

/** Whether `needle` appears in `haystack`, raw or as base64url text inside the records. */
function contains(haystack: { records: Record<string, unknown>[]; parts: Uint8Array[] }, needle: Uint8Array): boolean {
  const asText = Buffer.from(needle).toString("base64url");
  const asHex = Buffer.from(needle).toString("hex");
  const json = JSON.stringify(haystack.records);
  if (json.includes(asText) || json.includes(asHex)) return true;
  return haystack.parts.some((part) => Buffer.from(part).includes(Buffer.from(needle)));
}

describe("SP-01: the server holds no key that opens items, and no plaintext", () => {
  it("after every kind of operation, no key or plaintext appears in what the server stored", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const alice = members.alice!;
    const plaintexts = [text("item content: the secret"), text("submission: also secret"), text("meta stays secret")];
    await aliceTeam.createItem("item-1", [{ content: plaintexts[0]!, meta: plaintexts[2]! }]);
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    await submit(outsider(w.server.anonymous()), linkKey, "team-1", "inbox-1", [{ content: plaintexts[1]! }]);
    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob"] });
    await members.bob!.vault.rekey("team-1");
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: ["bob"] });
    await alice.vault.changePin("2222");
    await alice.vault.replaceRecoveryPhrase();
    await alice.vault.rotate({ pin: "2222" });

    const session = await alice.vault.openTeam("team-1");
    const secrets: Uint8Array[] = [
      ...plaintexts,
      alice.vault.requireAccount().key,
      (await alice.localKeys.getDevice("alice"))!.deviceKey,
      await session.teamKey(1),
      await session.teamKey(2),
      await session.teamKey(3),
      decodeLinkKey(await session.shareLinkKey("item-1")),
    ];
    for (const who of [alice, members.bob!]) {
      const { pairs } = await bundleOf(who.vault);
      secrets.push(pairs.signing.secretKey.subarray(0, 32), pairs.encryption.secretKey, pairs.teamStateKey);
    }
    const stored = w.server.dump();
    for (const secret of secrets) expect(contains(stored, secret)).toBe(false);
    // The scan does find what is stored: public keys.
    expect(contains(stored, (await bundleOf(alice.vault)).pairs.signing.publicKey)).toBe(true);
  });
});
