# Hardening direction

When a finding changes the protocol, and what a change may cost. Reviews ([protocol-review](../skills/protocol-review/SKILL.md)) and changes ([protocol-change](../skills/protocol-change/SKILL.md)) apply this guide.

**Why.** Reviews 004 to 013 found ever narrower attacks: the server together with a stolen device, often with an integration mistake. Most fixes added remembered state (anchors, floors, roots) and fallbacks, which the next review then attacked. Protection grew deep in one corner while comparable risks stayed accepted elsewhere, and the cost moved to integrators (new duties and ports) and users (new failures that need a human). The library must stay product-agnostic, easy to embed and platform-neutral: hardening is worth its cost only against attacks a product would plausibly meet.

## The action rule

Severity ([rubric](../skills/protocol-review/SKILL.md#severity-rubric)) measures harm. This rule decides what to do about it.

| Finding | Default disposition |
| --- | --- |
| One actor alone (the server, a stolen device, a leaked credential, a session, a member, an owner key), with no integration error | **Fix** in the protocol |
| Needs two actors, an integration error, or a window that closes by itself | **Accept and document**: a threat's Limit or disposition, the integration guide when the integration can prevent it, a ledger residual. Add detection when it is cheap. Fix only with a free or small change (below) |
| Availability only | Accept, unless a small change fixes it |
| Overclaim, wrong or stale text | **Correct the text**, always |

A finding the rule says to accept is fixed anyway only by the user's decision, recorded in the plan. A combined attack that is really one actor in practice (a script in the vault holds the session too) counts as one actor: say why in the finding.

## Complexity budget

Every proposed fix states its **delta**: rules and branches, inputs and fallbacks, local or server state, public API surface, integration duties, and user-visible failures (errors or warnings someone must act on).

| Class | What it is | Allowed for |
| --- | --- | --- |
| **Free** | Deletes or merges at least what it adds | Any finding |
| **Small** | One field, check, error reason or sentence; no new state, fallback, duty or human step | Any finding the action rule fixes, and accepted ones when it is this cheap |
| **Costly** | New remembered state, a new root of trust, a new fallback, a new integration duty, or a new failure that needs a human | Only a one-actor finding, with the user's decision in the plan, naming what it could retire later |

Never fix a combined-actor finding with a fallback ("if X is missing, use Y"): whoever controls X chooses the branch, and the next review finds it.

## Product cost

Each fix and each plan says, in a line each:

- **Integrators:** new ports or methods, new duties, migration of stored data or handles.
- **Users:** new failure states, warnings and support steps.
- **Reach:** what gets worse for stateless devices, new browsers, split layouts or another platform.
- **API:** breaking changes to public types or operations.

## Deferred mechanisms

Residuals that need the same missing mechanism are grouped and point to it, instead of being patched one by one. A finding in a group is accepted with a pointer, unless the action rule says to fix it.

| Group | Residuals | Mechanism (a v2 project) |
| --- | --- | --- |
| **Server-controlled history** | Rollback, split views, forged first contact, planted or repaired anchors, a retired account version, a rewritten recovery key (TH-04, TH-05, TH-12, TH-20, TH-38, SP-19): 13 residuals, growing with almost every `adversarial` review (review 043 B); a product sends invites through its server (043 A) | Key transparency, or owner fingerprints compared out of band (D-11); expected to retire most anchor and floor rules (D-48, D-52, D-54, D-59). The first v2 project |
| **Author authenticity** | Any member can claim any author (TH-15, TH-50) | Author signatures (D-09) |
| **Owner compromise** | One stolen owner key is enough (TH-17) | Multi-owner approval |
| **Support restores** | Records withheld, deleted or garbled until support acts; archived wraps that still open; a restore that brings back an attacker's state (TH-28, TH-36, TH-45, TH-46, TH-48) | Restores the integration authenticates, with a bounded window (review 043 F) |
| **Session theft** | What a session thief does as the user before its sessions end: credentials replaced, keys published, bait keys (TH-11, TH-37, TH-45, TH-47) | Ending sessions first (D-43), or server-side credential checks (review 043 F) |
| **Cross-context channel** | Forged or substituted transfers (TH-39, TH-49) | A secret shared between contexts |

## Exit

The goal is a freeze: two clean reviews (the [stop rule](../skills/protocol-review/SKILL.md#stop-rule)), a formal model of the core flows, an external audit, then frozen vectors. Prefer work that moves there over another round on an accepted corner.
