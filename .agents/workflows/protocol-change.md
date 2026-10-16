# Workflow: change the protocol or the guarantees

**Use when** behaviour, a format, a rule or a guarantee needs to change, or when the spec is ambiguous during implementation.

The specs lead; code follows. Guide: [spec-docs](../guides/spec-docs.md).

## Steps

1. **Decision:** add or update a `D-` entry: problem, decision, rejected alternatives, consequence, status.
2. **Threats and properties:** add or update `TH-` entries (and the index), then the `SP-` entries they rely on, with Limits and Verification paths.
3. **Key hierarchy:** update the keys and lifecycle scenarios affected.
4. **Protocol:**
   - a layout change of a released record is a **new `v`** with a new encoder; the old one stays;
   - a primitive change is a new suite ([add-algorithm-suite](add-algorithm-suite.md));
   - new labels go in the §1 table; new errors and reasons in §9; new records in the §4 catalogue and §11.
5. **Vectors:** list new vector files in §13.
6. **Check:** `npm run check:spec` passes.
7. **Then implement** ([implement-from-spec](implement-from-spec.md)): readers in one release, writers in the next.

## Done when

- Decisions, threats, properties, hierarchy and protocol agree, `check:spec` passes, and released formats are untouched.
