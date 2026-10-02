package codesign

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestRemovalPlatformBindingIdentityWithoutACLRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) {
		t.Helper()
		if b, err := exec.Command("/bin/chmod", args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	command("+a", "everyone deny readsecurity", path)
	t.Cleanup(func() { command("-N", path) })
	if _, err := os.Stat(path); !errors.Is(err, os.ErrPermission) {
		t.Fatal("full-stat denial ineffective", err)
	}
	ctx := context.Background()
	value := sidebandCarrier(t, appledouble.File{})
	opts := VerifyOptions{StrictSideband: true, AppleDoubleFiles: map[string]appledouble.Value{"file": value}}
	inputs, err := prepareBundleSideband(ctx, dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got, err := inputs.carrier(file); err != nil || got != value {
		t.Fatal("held identity lost", got, err)
	}
	opts.AppleDoubleFiles["alias"] = value
	if _, err := prepareBundleSideband(ctx, dir, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatal("duplicate hard-link binding accepted", err)
	}
	// No content fallback may bypass a genuine content-read denial.
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	command("-N", path)
	command("+a", "everyone deny read,readsecurity", path)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrPermission) {
		t.Fatal("combined full-stat denial ineffective", err)
	}
	if file, err := os.Open(path); err == nil {
		file.Close()
		t.Fatal("combined data denial ineffective")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	delete(opts.AppleDoubleFiles, "alias")
	if _, err := prepareBundleSideband(ctx, dir, opts); !errors.Is(err, os.ErrPermission) {
		t.Fatal("combined ACL/data denial bypassed", err)
	}
}
