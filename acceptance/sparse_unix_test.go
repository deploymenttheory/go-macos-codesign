//go:build !windows

package acceptance

import "os"

// Truncation of a new file already leaves its unwritten extent sparse.
func prepareSparseFixture(*os.File) error { return nil }
