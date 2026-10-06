//go:build !windows

package codesign

import "os"

func prepareCommandSparseFixture(*os.File) error { return nil }
