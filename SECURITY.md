# Security policy

> Authoring guide. Fill this when a public release is close, after the design documents under `docs/`. Do not publish a reporting channel until GitHub private vulnerability reporting is turned on for the repository. A placeholder address is worse than none.

## Role

Answers: **how should vulnerabilities be reported and handled?**

This is project governance, not a description of the cryptography. The design lives in:

- [docs/threat-model.md](docs/threat-model.md) — assets, adversaries, assumptions, `TH-` ids
- [docs/security-properties.md](docs/security-properties.md) — guarantees and how they are checked, `SP-` ids
- [docs/key-hierarchy.md](docs/key-hierarchy.md) — keys and lifecycle
- [docs/protocol.md](docs/protocol.md) — algorithms, envelopes, and operations

## Audience

Security researchers, users, maintainers.

## Sections to write before publication

### Supported versions

A table of which released versions still receive security fixes. Omit it until versions exist. Do not list `0.0.0` as supported.

### Reporting a vulnerability

The private channel. Use GitHub private vulnerability reporting. Say explicitly that exploitable issues must not be filed as public GitHub issues.

A useful report includes:

- Affected version or commit.
- The `TH-` or `SP-` id when one applies.
- Impact and a minimal reproduction.
- Whether the reporter wants credit.

### Disclosure and coordination

How long the reporter should wait, who is told, and when a public advisory is published.

### Security updates

How fixes ship (release, advisory) and where users should look.

### Support limitations

What the project does not promise. Include the audit status honestly, for example that the project has not had an independent security audit, until that changes.

## Not yet in force

Private vulnerability reporting is not configured. There is no disclosure address in this file on purpose.
