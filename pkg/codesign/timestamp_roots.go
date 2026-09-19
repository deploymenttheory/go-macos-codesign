package codesign

import (
	"bytes"
	_ "embed"
)

// Public Apple PKI roots, pinned and attributed in trust/manifest.json. These
// are explicit timestamp trust inputs, never a replacement for code-signer trust.
//
//go:embed trust/AppleRootCA.der
var appleTimestampRoot []byte

//go:embed trust/AppleRootCA-G2.der
var appleTimestampRootG2 []byte

//go:embed trust/AppleRootCA-G3.der
var appleTimestampRootG3 []byte

// AppleTimestampRoots returns independent copies of the bundled Apple PKI roots
// for callers explicitly choosing Apple's TSA. It never reads an OS trust store.
func AppleTimestampRoots() [][]byte {
	return [][]byte{bytes.Clone(appleTimestampRoot), bytes.Clone(appleTimestampRootG2), bytes.Clone(appleTimestampRootG3)}
}
