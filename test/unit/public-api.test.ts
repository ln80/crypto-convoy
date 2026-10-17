/**
 * The public surface (D-15): high-level operations and types only. No primitive, suite,
 * encoder or raw key is reachable from an entry point.
 */
import { describe, expect, it } from "vitest";
import * as browser from "../../src/browser/index.js";
import * as main from "../../src/index.js";
import * as testing from "../../src/testing/index.js";
import { TeamSession } from "../../src/team/session.js";
import { team } from "../support/teams.js";

describe("public API", () => {
  it("exports exactly these values from each entry", () => {
    expect(Object.keys(main).sort()).toEqual(
      ["ConvoyError", "RateLimitedError", "StoreConflictError", "createLinkClient", "createTeamKeyReceiver", "createVault", "isConvoyError", "version"].sort(),
    );
    expect(Object.keys(browser).sort()).toEqual(["createIndexedDbLocalKeyStore", "takeLinkKey"]);
    expect(Object.keys(testing).sort()).toEqual(["FakeOprfServer", "MemoryLocalKeyStore", "MemoryRecordStore", "fixedClock"]);
  });

  it("vaults and sessions expose no key, port or suite to the application", async () => {
    const { members, aliceTeam } = await team();
    const forbidden = /key|ports|suite|account$/i;
    const publicNames = (o: object) => [
      ...Object.getOwnPropertyNames(o),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(o)),
    ];
    // Names matching that return only link strings, sealed transfers or reports, or act on member keys.
    const allowed = ["shareLinkKey", "rekey", "accountId", "exportTeamKeys", "secureAccount"];
    const exposed = (o: object) => publicNames(o).filter((n) => forbidden.test(n) && !allowed.includes(n));
    expect(exposed(aliceTeam)).toEqual([]);
    expect(exposed(members.alice!.vault)).toEqual([]);
    expect(Object.getOwnPropertyNames(TeamSession).filter((n) => forbidden.test(n))).toEqual([]);
  });
});
