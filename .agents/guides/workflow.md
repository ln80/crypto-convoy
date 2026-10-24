# Workflow

## Spec → plan → execution

1. **Spec.** If the change alters behaviour, formats or guarantees, update `docs/` first ([protocol-change](../skills/protocol-change/SKILL.md)). Never implement what the protocol doesn't specify. Whether a risk is worth a change at all, and what the change may cost, is the [hardening direction](direction.md)'s.
2. **Plan.** Break the work into small steps, each with its tests. Once approved, copy the plan to `.agents/plans/NNN-name.plan.md` (next free number).
3. **Execution.** One commit per step. Append execution notes to the plan (what changed, deviations, follow-ups).
4. **Review.** A [protocol review](../skills/protocol-review/SKILL.md): `design` before a protocol plan is approved, `change` after it; `adversarial`, `complexity` and `residuals` every few plans, as the [ledger](../reviews/ledger.md) shows.

## Before each commit

- `npm run typecheck`
- `npm test` (and `npm run test:fuzz` when a parser changed)
- `npm run check:spec` when `docs/` changed
- `npm run build` when the structure, exports or dependencies changed
- The traceability test is green: every non-deferred property has its tests.

## Format and algorithm changes

- New record layout: new `v`, new encoder `case`, new vectors; readers first, writers in the next release.
- New algorithms: a new suite ([add-algorithm-suite](../skills/add-algorithm-suite/SKILL.md)).
- New link value format: a new prefix character.

## Learning notes

When a change teaches a new pattern, concept or lesson, record it in `learning/` (local, not tracked) with [capture-learning](../skills/capture-learning/SKILL.md). When a decision or a public operation changes, update `learning/course/` with [maintain-course](../skills/maintain-course/SKILL.md). The short notes stay design history. The course says when one describes a deferred or superseded decision.
