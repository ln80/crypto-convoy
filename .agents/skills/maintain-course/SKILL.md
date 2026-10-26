---
name: maintain-course
description: "Update crypto-convoy's local protocol course in learning/course when the protocol, a decision, or the public API changes. Correct stale lessons before adding lifecycles, state diagrams, or comparisons. Use when the user asks to update, extend, or maintain the course."
---

# Workflow: maintain the protocol course

**Use when** the protocol, a decision, or the public API changed, or when extending `learning/course/`. The course is local and gitignored. The short notes in `learning/patterns/`, `learning/concepts/`, and `learning/lessons/` are design history. Do not rewrite them to match a deferred or superseded decision. The course says when a note describes one, and a note whose concept the protocol retired gets a status line (see [Retired concepts](#retired-concepts-preserve-and-mark)).

## Order

1. **Correctness before new lessons.** Read the decision status in `docs/decisions.md` and the operation in `docs/protocol.md`. A lesson or diagram that shows a removed record as current is a bug; the fix is to mark it retired, not to delete it (below).
2. **Lifecycles.** One lesson per lifecycle, not per method. A public operation in protocol §12 appears in exactly one lesson.
3. **Elsewhere.** Only when that decision has a Rejected line. Four to eight sentences after the code: the other construction, the property it aims at, and the Rejected line. No second course.

## Retired concepts: preserve and mark

When the protocol stops using a record, key, check or technique that is still a sound idea, the course keeps it and says it is no longer used. A reader learns more from "we did this, here is why it went, here is what replaced it" than from a gap. Deleting a concept only because the protocol no longer has it is a bug.

- **Mark it.** Where the concept is taught, add a callout before its technique:

  ```markdown
  > [!warning] No longer used (D-NN)
  > Since D-NN the protocol doesn't use X. What replaced it: Y ([[course/…|lesson]], §N). Why: one sentence from the decision's Problem.
  ```

  With no replacement, say "Nothing replaces it:" and what covers the risk now, or the accepted residual.
- **Keep the teaching.** The problem, the technique and its diagram stay, in the past tense where they describe what the protocol did. The diagram's title says "(retired, D-NN)". The concept stays valid on its own terms; the callout says why this protocol dropped it.
- **Code.** Quoted code must exist. Quote the last version from git, with the commit on the line above (`src/team/anchors.ts@<commit>:12-40`), or show the current code that replaced it.
- **Whole lessons.** A lesson whose subject is retired stays, with the callout at the top, and the chapter index lists it under a "Retired" heading with the decision. Its check stays; its answer says what the protocol does now.
- **Current lessons.** A lesson about what replaced it links back to the retired one in one sentence ("this replaced [[…]]").
- **Notes.** A note in `patterns/`, `concepts/` or `lessons/` keeps its body; add one line under its title: "Not used by the protocol since D-NN: replaced by …".
- **Not shipped vs retired.** Designs recorded and never in the protocol (deferred, rejected before release) stay in `06-not-shipped`. Concepts the protocol used and then removed are retired where they were taught.

## Lesson shape

Obsidian markdown. Frontmatter `tags: [course, chapter/…]`. Problem and Predict are callouts (`> [!failure]`, `> [!question]`). A scar is `> [!bug]`. Technique, diagram, and code are headings. Code is a `ts` fence with the path and line numbers on the line above, quoted from the file. Answers live only in that chapter's `answers.md`, under a heading the check links to with a path, `[[course/…/answers#Heading]]`.

## Diagrams

Mermaid only. No colors, no `style`, no `classDef`. One screen. A box is a key, a record, or a check that exists now.

| Kind | Use for |
| --- | --- |
| `stateDiagram-v2` | A few named states and forbidden arrows: vault status, team access, owner-overview status |
| `sequenceDiagram` | A call that crosses the vault, the server, another member, or a second context |
| `flowchart` | A key relationship or a pure plan |

No diagram for a length check, a label, or a single MAC.

## Stale terms

These names are not in v1. A lesson may use them only in `06-not-shipped`, or under a "No longer used" callout, and either one states the decision status:

- a `grant` record, `grantOp`, holding a version by a grant
- `invite` record, `inviteMac`, `createInvite`, a join secret, `autoApproveInvites`
- a continuity signature, proof kind `continuity` or `invite`
- the `team-state` record, `teamStateKey`, a compare-and-set write on `revision`, the reasons `state_conflict` and `state_unreadable`, a bundle without a floor (retired by D-66)

Current rules the course must match: D-37 (roster only; every access change is a rotation), D-32 deferred (an invite link is an anchor), D-38 (proof is `recovery` or `none`), D-39 (a wrap replacement is `replace`; the previous live record is archived), D-66 (every bundle holds a floor; a team's roots are the floor, the local anchor and the vault's anchor).

## Done when

- Chapter indexes and answer headings match the lessons.
- Every §12 operation is named in one lesson.
- A cited `D-` / `SP-` / `§` exists in `docs/`.
- Wikilinks to removed lesson filenames are gone.
- Every retired concept the course teaches carries a "No longer used" callout naming the decision and what replaced it; nothing was deleted only because the protocol stopped using it.
