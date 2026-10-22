# Workflow: review the specs for divergence

**Use when** a plan changed `docs/`, before a release or a freeze, or when asked to check that the threat model, the properties and the protocol still agree. It finds what `check:spec` can't: claims nothing delivers, claims the code contradicts, and threats nobody listed.

Read only: the review writes a findings file and changes no spec or code. Fixes go through [protocol-change](protocol-change.md).

## Steps

1. **Baseline.** Run `npm run check:spec`; note its failures and `known` notes. Read the latest plan and `git log` since the last review in `.agents/reviews/`.
2. **Read in order:** [threat model](../../docs/threat-model.md), [security properties](../../docs/security-properties.md), [protocol](../../docs/protocol.md), then [decisions](../../docs/decisions.md) and the [server contract](../../docs/scope.md#server-contract). Also skim `key-hierarchy.md`, `integration.md` and `using.md`, which repeat claims.
3. **Properties → protocol.** For each sentence of each non-deferred property, name the § that delivers it. A sentence with no § is an **overclaim**: either the protocol is missing a step, or the property needs a Limit.
4. **Threats → mechanism.** For each mitigated threat, check that its actor really can't do the attack with what the protocol allows, and that the property it cites says so. For each "detected", "refused with" or "reported" claim, find the code path in `src/` or the test that produces exactly that error, reason or report.
5. **Actors × operations.** For each actor (A1–A11), and especially for whoever holds an unlocked vault or a session, go through every public operation (§12) and ask what they gain by calling it. A harmful result that no threat names is a **missing threat**.
6. **Decisions → text.** For each decision since the last review, search for what it changed in every document. Wording that still describes the old behaviour is **stale**; add it to `scripts/retired-terms.json` when you file the finding.
7. **Spec → code.** Where the testing kit (`src/testing/`) or the library behaves differently from §11 or §5–§7, record which one is right, if you can tell.
8. **Write** `.agents/reviews/NNN-name.md` (next free number). Each finding: an id (letters A, B, … within the review), its kind (overclaim, missing threat, wrong claim, stale text), severity, the files and lines, the evidence, and whether fixing it needs a decision or only an edit.

## Done when

- Every non-deferred property, every mitigated threat and every decision since the last review was checked, and the findings file says so.
- Findings that only need an edit are listed separately from those that need a decision, so the edits can be done right away.
