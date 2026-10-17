// Runs the built package as a consumer would: no test setup, no source files.
// `npm run test:package` after `npm run build`.
import { createLinkClient, createTeamKeyReceiver, createVault } from "crypto-convoy";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore } from "crypto-convoy/testing";
import { takeLinkKey } from "crypto-convoy/browser";

const server = new MemoryRecordStore();
const keys = new MemoryLocalKeyStore();
const settings = { argon2: { write: { opslimit: 2, memlimit: 64 * 1024 * 1024 } } };
const vault = await createVault({ store: server.as("a"), oprf: new FakeOprfServer(), deviceKeys: keys, anchors: keys, settings }, "a");
await vault.setup("1234");
await vault.confirmRecoveryPhrase(vault.beginRecoverySetup().recoveryPhrase);
await vault.createTeam("t");
const team = await vault.openTeam("t");
const draft = team.beginItem();
const ciphertext = draft.addPart(new TextEncoder().encode("ok"));
await draft.seal("i");

const client = await createLinkClient();
const shared = client.openSharedItem(await team.shareLinkKey("i"), "t", "i", await server.anonymous().get({ type: "item", teamId: "t", itemId: "i" }));
const receiver = await createTeamKeyReceiver("a", "t");
const page = await receiver.openTeam({ store: server.as("a"), anchors: new MemoryLocalKeyStore() }, await vault.exportTeamKeys("t", receiver.request));
const fromPage = await (await page.openItem("i")).part(0, ciphertext);
if (new TextDecoder().decode(await shared.part(0, ciphertext)) !== "ok" || new TextDecoder().decode(fromPage) !== "ok" || typeof takeLinkKey !== "function") {
  throw new Error("package smoke test failed");
}
console.log("package smoke test passed");
