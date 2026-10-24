/**
 * SP-01: The server never holds a key that opens items.
 * Threats: TH-01, TH-29.
 */
import { vaultInternals } from "../../src/account/vault.js";
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { decodeLinkKey } from "../../src/encoding/link.js";
import { bundleOf } from "../support/forge.js";
import { outsider } from "../support/link-client.js";
import { ContentStore } from "../support/content-store.js";
import { team, keysHandle } from "../support/teams.js";
import { replacePhrase } from "../support/fixtures.js";

const text = (s: string) => new TextEncoder().encode(s);

/** Whether `needle` appears in what was stored, raw or as base64url or hex text inside records. */
function contains(stored: { records: unknown[]; parts: Uint8Array[] }, needle: Uint8Array): boolean {
  const json = JSON.stringify(stored.records);
  if (json.includes(Buffer.from(needle).toString("base64url")) || json.includes(Buffer.from(needle).toString("hex"))) return true;
  return stored.parts.some((part) => Buffer.from(part).includes(Buffer.from(needle)));
}

describe("SP-01: no key that opens items, and no plaintext, in the key store or the content storage", () => {
  it("after every kind of operation", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const alice = members.alice!;
    const content = new ContentStore();
    const plaintexts = [text("item content: the secret"), text("submission: also secret"), text("meta stays secret")];
    const draft = aliceTeam.beginItem();
    content.put("item-1", 0, draft.addPart(plaintexts[0]!, { meta: plaintexts[2]! }));
    await draft.seal("item-1");
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const sender = (await outsider()).beginSubmission(linkKey, "team-1", "inbox-1");
    content.put("sub-1", 0, sender.addPart(plaintexts[1]!));
    content.putRecord("sub-1", await sender.seal("sub-1"));
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    await members.bob!.vault.rekey("team-1");
    await aliceTeam.owner().rotate({ keep: ["bob"], approve: [await keysHandle(aliceTeam, "bob", 2)] });
    await alice.vault.changePin("2222", { currentPin: "1234" });
    const { recoveryPhrase } = await replacePhrase(alice.vault, { currentPhrase: alice.recoveryPhrase });
    await alice.vault.rotate({ phrase: recoveryPhrase, newPin: "2222" });

    const session = await alice.vault.openTeam("team-1");
    const internals = sessionInternals(session);
    const secrets: Uint8Array[] = [
      ...plaintexts,
      vaultInternals(alice.vault).account().key,
      (await alice.localKeys.getDevice("alice"))!.deviceKey,
      await internals.teamKey(1),
      await internals.teamKey(2),
      await internals.teamKey(3),
      decodeLinkKey(await session.shareLinkKey("item-1")),
    ];
    for (const who of [alice, members.bob!]) {
      const { pairs } = await bundleOf(who.vault);
      secrets.push(pairs.signing.secretKey.subarray(0, 32), pairs.encryption.secretKey, pairs.teamStateKey);
    }
    const stored = { records: [...w.server.dump(), ...content.all().records], parts: content.all().parts };
    for (const secret of secrets) expect(contains(stored, secret)).toBe(false);
    // The scan does find what is stored: public keys.
    expect(contains(stored, (await bundleOf(alice.vault)).pairs.signing.publicKey)).toBe(true);
  });
});
