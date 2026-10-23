# CLAUDE.md

@AGENTS.md

## Claude Code specifics

- `src/CLAUDE.md`, `test/CLAUDE.md` and `docs/CLAUDE.md` import their folder's `AGENTS.md` and the matching guides from `.agents/guides/`, so the guides load in full.
- Skills load from `.claude/skills`, a symlink to `.agents/skills/`: `implement-from-spec`, `add-algorithm-suite`, `security-property-tests`, `protocol-change`, `protocol-review`, `capture-learning`, `maintain-course`.
- Keep instructions in `AGENTS.md` and `.agents/` only, so every agent reads the same rules.
