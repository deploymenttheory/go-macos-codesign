---
name: Feature request
about: Propose a codesign compatibility or portability improvement
title: 'Feature: '
labels: feature
assignees: ''
---

## Requested behavior

Describe the use case and the native `codesign` option, format or behavior involved.
Check docs/compatibility.md and spec/compatibility.json for existing coverage.

## Expected result

Provide an example command and expected result. Identify the macOS reference
version where known, and how an independent acceptance test could verify it.

## Portability and references

Describe any dependence on host state, keychains or non-exportable keys. Link
relevant Apple source, Clang AST facts or other implementation references.
Production must remain pure Go and work without Apple services.

## Related work

Link related issues, roadmap entries or PRs, and explain any ordering dependency.
