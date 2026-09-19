## Change

Describe the concrete problem and resulting behavior. Link any related issue.
For a dependent PR, identify its prerequisite and merge order.

## Evidence and validation

- Relevant source/Clang AST or native comparison:
- Local checks and actual CI run:
- Coverage/native acceptance changes, when applicable:
- Remaining compatibility limits:

## Review checklist

- [ ] Production remains pure Go with no Apple framework, subprocess or CGO dependency.
- [ ] Relevant tests and checks pass; every production package remains above 95% coverage.
- [ ] Capability docs, progress/roadmap, changelog and compatibility inventory reflect the change.
- [ ] Fixtures retain source hashes and provenance; no private identities or passwords were added.

For documentation-only changes, mark implementation-specific items not applicable
and describe link/example validation instead of adding unrelated tests.
