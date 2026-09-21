//go:build !darwin

package acceptance

import (
	"os"
	"testing"
	"time"
)

func executableDirectoryAccess(_ *testing.T, _, _, _ os.FileInfo, _, _, _ bool, _, _ time.Time) map[string]any {
	return nil
}
