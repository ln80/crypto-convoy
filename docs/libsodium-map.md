# libsodium map

> Status: draft. Kept in step with `src/suites/` by `test/unit/libsodium-map.test.ts`.

## Role

Answers: **which libsodium function does each protocol task, and what is checked before calling it?**

Every primitive goes through the suite registry ([architecture guide](../.agents/guides/architecture.md)); only `src/suites/` calls libsodium (`libsodium-wrappers-sumo`). This page maps each call to the suite method that wraps it and the protocol task it serves. The protocol ([protocol.md](protocol.md)) remains the reference for what is computed.

## Audience

Implementers porting the protocol to another language, reviewers, auditors.

## libsodium functions (suite `cc1`)

| libsodium | Suite method | Protocol task | Checked before the call | Source |
| --- | --- | --- | --- | --- |

## Other primitives

Not from libsodium, each for a stated reason.

| Library and function | Protocol task | Why not libsodium | Source |
| --- | --- | --- | --- |
