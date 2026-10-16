# Workflow: write the tests for a security property

**Use when** a property (SP-) has no tests yet, or a change touches what a property guarantees.

## Steps

1. **Read the property:** its statement, Limit, Assumptions, Verification paths and related threats (TH-). Read each threat's Attack.
2. **Create or open** each test file named under Verification. Add the header citing the SP and TH ids (guide: [testing](../guides/testing.md)).
3. **One test per attack:** turn each threat's attack into a scenario with the fake store's tamper hooks (swap, replay, rollback, drop, fork, garbage, withhold).
4. **Assert precisely:** the exact error code and reason, the resulting team state (for example `unverified`), and that no plaintext or key was returned.
5. **Test the Limit** as specified behaviour, so a future change that silently alters it is noticed.
6. **Add the honest path** once, to show the operation still works when nothing is tampered with.
7. **Prove the guard:** for each attack test, temporarily remove the check it relies on and confirm the test fails.
8. Run `npm run test:security` and the traceability test.

## Done when

- Every attack in the related threats has a failing-closed test, the Limit is pinned, the traceability test passes.
