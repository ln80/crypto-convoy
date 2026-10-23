---
name: protocol-change
description: "Change crypto-convoy's protocol or guarantees spec-first: decision, threats, properties, key hierarchy, protocol (new versions, labels, errors), vectors, then check:spec, before any code. Use when the spec is missing, ambiguous or must change."
---

# Workflow: change the protocol or the guarantees

**Use when** behaviour, a format, a rule or a guarantee needs to change, or when the spec is ambiguous during implementation.

The specs lead; code follows. Guide: [spec-docs](../../guides/spec-docs.md).

## Steps

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
8. **Design review:** a [protocol review](../protocol-review/SKILL.md) in `design` mode of the decision, before the plan is approved; the plan cites it.
9. **Then implement** ([implement-from-spec](../implement-from-spec/SKILL.md)): readers in one release, writers in the next.

## Done when

- Decisions, threats, properties, hierarchy and protocol agree, `check:spec` passes, and released formats are untouched.
- After a plan that changes `docs/`, a [protocol review](../protocol-review/SKILL.md) in `change` mode finds nothing new, or its findings are recorded in the ledger.
