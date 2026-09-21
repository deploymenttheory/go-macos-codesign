package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
	"golang.org/x/sys/unix"
)

func TestBundleDirectoryMetadataFailureBeforeCommit(t *testing.T) {
	app := testBundle(t)
	main := filepath.Join(app, "Contents/MacOS/hello")
	before := readTestFile(t, main)
	if err := unix.Chflags(app, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(app, 0) })
	if err := Sign(context.Background(), app, SignOptions{}); !errors.Is(err, hostmeta.ErrUnsupportedDirectoryStat) {
		t.Fatal(err)
	}
	if !bytes.Equal(readTestFile(t, main), before) {
		t.Fatal("executable committed after metadata failure")
	}
	entries, err := os.ReadDir(filepath.Join(app, "Contents/_CodeSignature"))
	if err != nil || len(entries) != 0 {
		t.Fatal("expected empty directory after metadata failure", entries, err)
	}
	assertNoBundleStaging(t, app)
}
