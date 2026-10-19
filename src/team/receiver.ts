// The receiving side of a team key transfer (§3.8, D-29): one receiver, one transfer.
import { decodeAnchor } from "../encoding/link.js";
import { decryptionFailed, isConvoyError, trustFailure } from "../errors.js";
import { callPort, resolveSettings, systemClock, type AnchorStore, type Clock, type RecordStore, type Settings } from "../ports.js";
import { parseMemberKeys } from "../records/member-keys.js";
import { bundleKeyPairs } from "../records/member-keys-wrap.js";
import { encodeRequest, openTransfer } from "../records/transfer.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";
import type { MemberBundle } from "./context.js";
import { TeamSession } from "./session.js";

export interface ReceiverPorts {
  readonly store: RecordStore;
  /** The team sessions' half of local storage. */
  readonly anchors: AnchorStore;
  readonly clock?: Clock;
  readonly settings?: Settings;
}

export interface TeamKeyReceiver {
  /** Send this to the vault (`exportTeamKeys`) over the integration's channel. */
  readonly request: string;
  /**
   * Opens the vault's transfer and the team (§3.8 steps 3–4). Works once. On a first open, pass
   * the invite link's `anchor`: the chain must contain it (§6.4), as with `vault.openTeam`. Throws
   * `UNSUPPORTED_VERSION`, `DECRYPTION_FAILED` (another receiver, account or team, or a second use),
   * `MALFORMED_RECORD` (a malformed anchor leaves the receiver unused); a bundle not matching its
   * published keys, or a chain without the anchor, gives an `unverified` session.
   */
  openTeam(ports: ReceiverPorts, transfer: string, options?: { anchor?: string }): Promise<TeamSession>;
}

/** A receiver for one team's keys, in the context that will do that team's work. Loads libsodium. */
export async function createTeamKeyReceiver(accountId: string, teamId: string): Promise<TeamKeyReceiver> {
  await ready();
  const suite = CURRENT_SUITE;
  const pair = suite.generateEncryptionKeyPair();
  let used = false;
  return {
    request: encodeRequest(pair.publicKey),
    async openTeam(ports, transfer, options = {}) {
      // Validate before crypto (§8): a malformed anchor doesn't use up the receiver.
      const anchor = options.anchor !== undefined ? decodeAnchor(options.anchor) : undefined;
      if (used) throw decryptionFailed();
      used = true;
      let opened;
      try {
        opened = openTransfer(suite, pair, { accountId, teamId }, transfer);
      } finally {
        suite.wipe(pair.secretKey);
      }
      const teamPorts = {
        suite,
        store: ports.store,
        anchors: ports.anchors,
        clock: ports.clock ?? systemClock,
        settings: resolveSettings(ports.settings),
      };
      const bundles: MemberBundle[] = [];
      try {
        for (const bundle of opened) {
          const json = await callPort(() =>
            ports.store.get({ type: "member-keys", teamId, accountId, memberKeysVersion: bundle.memberKeysVersion }),
          );
          const published = parseMemberKeys(json, { teamId, accountId, memberKeysVersion: bundle.memberKeysVersion });
          const pairs = bundleKeyPairs(suite, bundle);
          const matches =
            suite.equal(pairs.signing.publicKey, published.signingPublicKey) &&
            suite.equal(pairs.encryption.publicKey, published.encryptionPublicKey);
          if (!matches) throw trustFailure("key_mismatch");
          bundles.push({ memberKeysVersion: bundle.memberKeysVersion, published, pairs });
        }
      } catch (error) {
        if (isConvoyError(error, "TRUST_FAILURE")) return TeamSession.failed(teamPorts, accountId, teamId, error);
        throw error;
      }
      return TeamSession.open(teamPorts, accountId, teamId, bundles, anchor);
    },
  };
}
