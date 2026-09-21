//go:build !darwin

package acceptance

import (
	"os"
	"testing"
	"time"
)

func executableDirectoryUnaccessed(_, _ os.FileInfo) bool { return false }

func executableDirectoryAccess(_ *testing.T, _, _, _ os.FileInfo, _ bool, _, _ time.Time) map[string]any {
	return nil
}
