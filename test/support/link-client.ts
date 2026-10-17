// An outside client: no account and no store (§7.3, §7.5).
import { createLinkClient } from "../../src/content/link-client.js";

export const outsider = () => createLinkClient();
