# Resource traversal evidence

These native macOS 27.0.1 observations explain the resource-error regression in
PR107. A final file archive does not encode directory enumeration order. Removing
incidental native attribute files can leave reusable FAT directory slots; restoring
an attribute file later may place it before resources copied earlier.

The parent records contain actual host/compiler/binary identity, source hashes and
both compressed SDK ASTs. The other records contain native FTS traversal and
attribute observations or full bundle archives, actual diagnostics and exit codes.
They were captured by the checked-in C probe and acceptance tests, not inferred
from an OS version or generated from Go's expected result.

- `TestNativeSigningProfileResourceOrder` retains all twelve original native
  default/serial repetitions and now predicts the exact first failure from an
  independent SDK traversal trace.
- `TestFilesystemMetadataResourceOrder` adds both resource-first and nested-first
  creation sequences on FAT32 and exFAT. The complete archived contents must match
  across creation orders and between Go/native copies. Diagnostics must differ as
  predicted, and failed signing must preserve every data fork.
  The nested-first setup keeps its early directory entry while restoring its
  captured bytes in place. It creates `Info.plist` before restoring its metadata,
  then copies the rest of the tree. Deleting/recreating the carrier or creating
  it before its data file does not establish the same order across filesystem
  drivers. Setup logs directory order at each stage and asserts the final order.
- Linux and Windows run both creation sequences on real mounted volumes. macOS
  15/26/27 additionally run the native C oracle and both-target Clang extraction.
  This local capture does not claim foreign or other-version runtime results.

Reproduce in a new, empty output directory:

```sh
MACOSCODESIGN_EVIDENCE_DIR=/tmp/codesign-resource-order-new \
  go test -count=1 -json ./acceptance \
  -run '^Test(FilesystemMetadataResourceOrder|NativeSigningProfileResourceOrder)$'
```

Keep complete output and provenance together when refreshing the capture. Do not
rewrite source hashes to make an old capture appear current. Existing module-bound
filesystem seeds must first be regenerated if the dependency changes.

The probe uses the FTS options from
[Apple's ResourceBuilder constructor](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/resources.cpp).
Its ASTs establish real SDK traversal/attribute declarations, not a reconstruction
of the private Security implementation. The source's default/serial dispatch
behavior and deep-signing completion remain separate scheduling obligations.
