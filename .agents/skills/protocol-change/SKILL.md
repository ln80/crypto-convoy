---
name: protocol-change
description: "Change crypto-convoy's protocol or guarantees spec-first: decision, threats, properties, key hierarchy, protocol (new versions, labels, errors), vectors, then check:spec, before any code. Use when the spec is missing, ambiguous or must change."
---

# Workflow: change the protocol or the guarantees

**Use when** behaviour, a format, a rule or a guarantee needs to change, or when the spec is ambiguous during implementation.

The specs lead; code follows. Guides: [spec-docs](../../guides/spec-docs.md), [hardening direction](../../guides/direction.md).

## Steps

0. **Gate.** Name what the change answers: a finding the [action rule](../../guides/direction.md#the-action-rule) says to fix, a product need, or a simplification. State its delta and [budget class](../../guides/direction.md#complexity-budget), and its [product cost](../../guides/direction.md#product-cost). A costly change needs a one-actor finding and the user's decision in the plan; for anything else, accept and document the risk instead (a threat's Limit, the integration guide, a ledger residual), and stop here.
1. **Decision:** add or update a `D-` entry: problem, decision, rejected alternatives, consequence, status.
2. **Ripple:** list the terms, operations and claims the decision changes. Search every file of `docs/` and `README.md` for each (not only the six specs: `integration.md`, `using.md` and `libsodium-map.md` repeat them), and update the older decisions, threats and properties that state them. Add the retired wording to `scripts/retired-terms.json` ([spec-docs](../../guides/spec-docs.md#after-every-edit)).
3. **Threats and properties:** add or update `TH-` entries (and the index), then the `SP-` entries they rely on, with Limits and Verification paths.
4. **Key hierarchy:** update the keys and lifecycle scenarios affected.
5. **Protocol:**
   - a layout change of a released record is a **new `v`** with a new encoder; the old one stays;
   - a primitive change is a new suite ([add-algorithm-suite](../add-algorithm-suite/SKILL.md));
   - new labels go in the §1 table; new errors and reasons in §9; new records in the §4 catalogue and §11.
6. **Vectors:** list new vector files in §13.
7. **Check:** `npm run check:spec` passes.
8. **Design review:** a [protocol review](../protocol-review/SKILL.md) in `design` mode of the decision, before the plan is approved; the plan cites it. When the review finds the change over budget, take its simpler alternative or accept the risk; don't add state to close the gaps it finds in the added state.
9. **Then implement** ([implement-from-spec](../implement-from-spec/SKILL.md)): readers in one release, writers in the next.

## Done when

- Decisions, threats, properties, hierarchy and protocol agree, `check:spec` passes, and released formats are untouched.
- The plan records the change's delta, budget class and product cost, and the decision's Consequence says what integrators and users must do differently.
- After a plan that changes `docs/`, a [protocol review](../protocol-review/SKILL.md) in `change` mode finds nothing new, or its findings are recorded in the ledger.
