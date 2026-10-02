package codesign

import (
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Content acquisition must not request unrelated ACL or EA read rights. The
// SDK confines the open, rejects final links and validates the held file type.
// Sideband queries acquire their own rights against this same held identity.
func openResourceFile(root *os.Root, name string) (*os.File, error) {
	return hostdata.OpenContentFileRead(root, name)
}
