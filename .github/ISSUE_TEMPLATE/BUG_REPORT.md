---
name: Bug report
about: Report unexpected signing, verification or CLI behavior
title: 'Bug: '
labels: bug
assignees: ''
---

## Problem

Describe the expected and actual behavior. Include the exact command, exit code,
stdout and stderr, with secrets removed.

## Reproduction

Provide a minimal reproduction using public test data where possible. Describe
the Mach-O form (arm64, x86_64 or universal), signing algorithm, identity format
and relevant options. Do not attach private keys, passwords or sensitive binaries.

## Environment

- Repository commit or snapshot:
- Operating system, version and architecture:
- Go version, if built locally:
- Native macOS baseline and `codesign` result, if compared:

## Evidence

Link a failing CI run or attach relevant redacted `artifacts/unit.jsonl`,
`artifacts/acceptance.jsonl` and `artifacts/provenance.json` output. If the result
differs from Apple, identify the first differing behavior or bytes.

For a potential vulnerability, follow SECURITY.md instead of publishing details.
