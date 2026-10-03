---
name: PostgreSQL-compatible SQL dialect
description: User prefers PostgreSQL-compatible SQL dialect as primary, with MySQL support as secondary
type: feedback
---

SQL dialect should be PostgreSQL-compatible first, with MySQL support added.

**Why:** PostgreSQL is the preferred database dialect. Seal SQL should be a subset of PostgreSQL, not a custom dialect.

**How to apply:** Use PostgreSQL syntax, types, and semantics as the baseline. Support MySQL syntax as an additional compatibility layer. Schema migration tools should support both pg_dump and mysqldump as sources.
