# Mach-O command-range evidence

This corpus qualifies signing operations when the Mach-O load-command region is large. It supplements the existing large-payload, dense-file, bundle, and resource-fork acceptance gates; it does not replace them or establish completion of Phase 2.

`macho-command-ranges.c` generates files using the host SDK's actual `mach_header_64`, segment, section, dylib, UUID, rpath, and build-version structures. A padded `LC_ID_DYLIB` enlarges the command region without allocating a giant producer buffer. Segment VM/file ranges remain aligned and the small executable-section controls contain a four-byte return instruction. These are signing-layout fixtures, not a claim that the dynamic loader can execute the generated dylibs. Native `codesign` acceptance and strict verification determine their signing behavior.

The eleven retained recipes are:

| Controls | Purpose |
| --- | --- |
| Small arm64 and x86_64 | Establish the recipe and native/portable equality before large cases. |
| 8,192 additional `LC_RPATH` commands | Exercise command-count growth independently of one oversized command. |
| A 65,536-byte dylib command | Exercise ordinary padded-command streaming. |
| Sectionless, without platform metadata | Qualify native CodeDirectory v20100 selection. |
| A real executable section, without platform metadata | Establish that a section alone does not enable executable-segment CodeDirectory fields. |
| `sizeofcmds = 1 GiB − 8`, `1 GiB`, and `1 GiB + 8` | Qualify the command-table boundary itself. |
| `sizeofcmds = 1 GiB − 40` and `1 GiB − 32` | With the 32-byte Mach-O header, qualify reads immediately below and exactly at the former 1 GiB allocation ceiling. |

Each recipe records initial bytes and the full-file size and SHA-256 after unsigned inspection, signing, signed inspection, strict verification, forced resigning, a forced dry run, removal, and final inspection. Diagnostics are retained with only the temporary operand path normalized. Ad-hoc signing uses an explicit identifier and disables timestamps. Large inputs are represented by deterministic recipes rather than checked-in gigabyte files.

The capture records the C generator, Go harness, supporting Apple evidence, native binary, and SDK-header hashes. Clang AST extraction for both arm64 and x86_64 records 31 SDK layout/constants facts. The separate `spec/apple-macho-command-policy.json` records seven complete pinned Apple method bodies, including first-build-version selection, legacy fallback, and platform-dependent executable-segment policy. SDK declarations are real; private interfaces in that extraction are declaration-only shims. Neither AST extraction is presented as executing Apple's private implementation.

## Run the complete qualification

Capture and compare the native oracle on macOS:

```sh
go run scripts/extract-macho-command-policy.go -check -out artifacts/apple-macho-command-policy.json
go run scripts/probe-macho-command-ranges.go -mode capture -check -out artifacts/macho-command-ranges-native.json
```

Replay every recipe using the portable public Go APIs on Linux, Windows, and macOS:

```sh
go run scripts/probe-macho-command-ranges.go -export-dir artifacts/macho-command-ranges
```

The replay compares every output's complete hash and native success/failure, checks inspection's architecture, identifier, CodeDirectory version, page size and CDHash, uses a 64 KiB configured working-storage budget, and requires working-file cleanup. That budget applies to managed working storage; it is not a claim that total process memory or owned inspection reports occupy 64 KiB. On macOS, add `-native-verify` to independently verify every accepted Go signing/resigning/dry-run result with Apple's binary.

The export directory must be empty. It receives 22 complete, gzip-compressed signed/resigned files and a manifest binding each file to its native hash/size, recipe, operation, corpus hash, producer platform, Go module files, and current production source hashes.

Download the Linux and Windows exports into separate immediate subdirectories, then verify them on macOS:

```sh
go run scripts/probe-macho-command-ranges.go -mode verify-import -import-dir artifacts/foreign-command-ranges
```

Both Linux and Windows producers are mandatory by default. If the macOS producer is included too, use `-required-hosts linux,windows,darwin`. Missing/duplicate producers, changed provenance, missing/extra entries, wrong sizes/hashes, damaged archives, and native verification failures fail the run. Every imported file is decompressed and hashed through a bounded buffer before native strict verification.

`-small` is a development aid for the six cheap controls. It is not used by complete qualification or CI acceptance and cannot replay a truncated corpus as a full one.
