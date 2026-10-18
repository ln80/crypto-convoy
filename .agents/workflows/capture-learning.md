# Workflow: capture a learning note

**Use when** a session produced a reusable pattern, an important concept, or a lesson from a mistake made or caught.

Notes live in `learning/` (local, ignored by git), one short file per note, with an index in `learning/README.md`.

## Steps

1. **Pick the kind:** `patterns/` (a reusable design), `concepts/` (a mechanism or vocabulary), `lessons/` (a mistake and the reflex it teaches).
2. **Check for an existing note** on the same idea; update it rather than duplicating.
3. **Write** `kebab-case-name.md`, at most about 25 lines, with this shape:
   ```
   # Name
   **In one line:** …
   **Why it matters:** …
   **How:** 2–5 bullets
   **Where we used it:** D-/SP-/TH-/AS- ids, protocol §
   **Pitfall:** …
   **Related:** links to other notes
   ```
4. **Index:** add one line to the matching section of `learning/README.md`: `- [Name](kind/file.md): the one-liner`.
5. **Check** that every link resolves and every cited id exists in `docs/`.

## Done when

- The note is short, plain, linked from the index, and cites only existing ids.
