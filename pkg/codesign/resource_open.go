package codesign

import (
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Content acquisition must not request unrelated ACL or EA read rights. The
// SDK confines the open, rejects final links and validates the held file type.
// Sideband queries acquire their own rights against this same held identity.
func openResourceFile(root *os.Root, name string) (*os.File, error) {
	return hostdata.OpenContentFileRead(root, name)
}

// Revalidate through the same content-only SDK contract used for hashing.
// A generic rooted stat can acquire unrelated ACL/EA rights on Windows.
func resourceUnchanged(root *os.Root, name string, source *os.File, before os.FileInfo) (result error) {
	current, err := openResourceFile(root, name)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, current.Close()) }()
	info, err := current.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, info) {
		return invalid("bundle resource changed: %s", name)
	}
	return sourceUnchanged(source, before)
}
