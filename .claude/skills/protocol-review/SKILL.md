---
name: protocol-review
description: "Review crypto-convoy's protocol in one of five modes: change (after a plan changes docs/), design (a proposal before code), adversarial (forgeable inputs, combined attackers, with a fresh-context reviewer), complexity (rules to delete or merge), residuals (accepted risks still acceptable). Reproduces findings, rates them with the severity rubric, writes .agents/reviews/NNN-name.md and updates the ledger. Read only. Use to review, harden or simplify the protocol, or before a freeze."
---

Follow [.agents/workflows/protocol-review.md](../../../.agents/workflows/protocol-review.md) step by step, together with the rules in [AGENTS.md](../../../AGENTS.md).

The mode comes from the arguments (`change`, `design`, `adversarial`, `complexity`, `residuals`). Without one, pick it from the workflow's "When" column and the [ledger](../../../.agents/reviews/ledger.md)'s stop-rule line, and say which.

The fresh-context reviewer (workflow step 3) is an Agent subagent (`general-purpose`), given only the mode's brief and the paths: never the plans, the reviews, the ledger or this conversation.
