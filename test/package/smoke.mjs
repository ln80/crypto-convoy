// Runs the built package as a consumer would: no test setup, no source files.
// `npm run test:package` after `npm run build`.
import { createLinkClient, createVault } from "crypto-convoy";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore } from "crypto-convoy/testing";
import { takeLinkKey } from "crypto-convoy/browser";

const server = new MemoryRecordStore();
const settings = { argon2: { write: { opslimit: 2, memlimit: 64 * 1024 * 1024 } } };
const vault = await createVault({ store: server.as("a"), oprf: new FakeOprfServer(), localKeys: new MemoryLocalKeyStore(), settings }, "a");
await vault.setup("1234");
const team = await vault.createTeam("t");
await team.createItem("i", [{ content: new TextEncoder().encode("ok") }]);
const client = await createLinkClient({ store: server.anonymous() });
const [part] = await client.openSharedItem(await team.shareLinkKey("i"), "t", "i");
if (new TextDecoder().decode(part.content) !== "ok" || typeof takeLinkKey !== "function") throw new Error("package smoke test failed");
console.log("package smoke test passed");
