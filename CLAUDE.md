# CLAUDE.md

@AGENTS.md

## Claude Code specifics

- Scoped guidance loads automatically from `src/CLAUDE.md`, `test/CLAUDE.md` and `docs/CLAUDE.md` (they import the matching guide from `.agents/guides/`).
- Skills (`.claude/skills/`) wrap the workflows in `.agents/workflows/`: `implement-from-spec`, `add-algorithm-suite`, `security-property-tests`, `protocol-change`, `spec-review`, `capture-learning`, `maintain-course`.
- Keep instructions in `AGENTS.md` and `.agents/` only, so Cursor and Claude Code read the same rules.
