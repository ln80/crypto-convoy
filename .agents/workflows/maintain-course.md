# Workflow: maintain the protocol course

**Use when** the protocol, a decision, or the public API changed, or when extending `learning/course/`. The course is local and gitignored. The short notes in `learning/patterns/`, `learning/concepts/`, and `learning/lessons/` are design history. Do not rewrite them to match a deferred or superseded decision. The course says when a note describes one.

## Order

1. **Correctness before new lessons.** Read the decision status in `docs/decisions.md` and the operation in `docs/protocol.md`. A diagram of a removed record is a bug.
2. **Lifecycles.** One lesson per lifecycle, not per method. A public operation in protocol §12 appears in exactly one lesson.
3. **Elsewhere.** Only when that decision has a Rejected line. Four to eight sentences after the code: the other construction, the property it aims at, and the Rejected line. No second course.

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

These names are not in v1. A lesson may use them only in `06-not-shipped`, and that lesson states the decision status:

- a `grant` record, `grantOp`, holding a version by a grant
- `invite` record, `inviteMac`, `createInvite`, a join secret, `autoApproveInvites`
- a continuity signature, proof kind `continuity` or `invite`

Current rules the course must match: D-37 (roster only; every access change is a rotation), D-32 deferred (an invite link is an anchor), D-38 (proof is `recovery` or `none`), D-39 (a wrap replacement is `replace`; the previous live record is archived).

## Done when

- Chapter indexes and answer headings match the lessons.
- Every §12 operation is named in one lesson.
- A cited `D-` / `SP-` / `§` exists in `docs/`.
- Wikilinks to removed lesson filenames are gone.
