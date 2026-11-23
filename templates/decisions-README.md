# Decisions (ADR-####)

File name: `ADR-####-<slug>.md`. Sections: status (proposed/approved/superseded) · context · options ·
decision · consequences · evidence. ADR-level decisions need the user's approval before they are marked
approved (engine strategy, stubbing a system, choosing a deviation, hook loading method).

Approved:
- [ADR-0001-engine-strategy](ADR-0001-engine-strategy.md) — our own build on UE 4.5.1 source, hooks as the test
  bench; phase order 4a → 4b → 4d → 4c, stay on 4.5.1 (2026-10-21, addenda 2026-10-21 / 22).
- [ADR-0002-hook-loading](ADR-0002-hook-loading.md) — proxy `VERSION.dll` + MinHook (2026-10-21).
- [ADR-0004-community-accounts](ADR-0004-community-accounts.md) — login/register API (TypeScript/Node + Postgres), alongside Steam (2026-10-21).
- [ADR-0005-launcher](ADR-0005-launcher.md) — own native launcher (C++, Media Foundation) with the original globe video and menu music (2026-10-21).
- [ADR-0006-matching-decompilation](ADR-0006-matching-decompilation.md) — phase 4d by matching decompilation: the
  original compiler and ATLAS's command lines as the judge, byte-identical functions as the acceptance criterion
  (2026-10-24; amended 2026-10-25: a function that differs only in a fatal log's source location counts as
  matching, Q-0017).

Proposed:
- [ADR-0007-load-testing-bots](ADR-0007-load-testing-bots.md) — load testing with a protocol-level bot client, and a
  test-only switch (REP-0003, off by default) that lets the original server admit bots from this PC (2026-10-24;
  deferred by the user the same day: real players will help test).

Planned:
- `ADR-0003-join-path` — how players join a community server without Steam's broken lookup (Q-0001..0003); the hosting
  options are in [hosting.md](../knowledge/hosting.md).
