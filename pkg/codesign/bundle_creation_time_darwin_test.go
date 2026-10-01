package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestBundleCreationTimePrecedesSecurityRestoration(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone deny writeattr", path).CombinedOutput(); err != nil {
		t.Fatalf("ACL: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	capture := func() any {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		m, err := hostdata.NewHeldMetadata(f)
		if err != nil {
			t.Fatal(err)
		}
		acl, err := m.CaptureACL()
		if err != nil {
			t.Fatal(err)
		}
		return acl
	}
	acl := capture()
	writes := []bundleWrite{
		{name: b.resourcesPath(), data: []byte("new resource envelope"), bundle: b, kind: bundleResourceWrite},
		{name: b.executable, data: []byte("new executable"), bundle: b},
	}
	if err := commitBundleWrites(context.Background(), writes); err != nil {
		t.Fatalf("writeattr ACL must not prevent replacement: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) || !bytes.Equal(readTestFile(t, path), writes[1].data) {
		t.Fatal("replacement was not committed")
	}
	if after.Sys().(*syscall.Stat_t).Birthtimespec != before.Sys().(*syscall.Stat_t).Mtimespec || before.Mode() != after.Mode() || !reflect.DeepEqual(acl, capture()) {
		t.Fatal("replacement lost expected creation time, mode or source ACL")
	}
	if !bytes.Equal(readTestFile(t, filepath.Join(app, b.resourcesPath())), writes[0].data) {
		t.Fatal("resource envelope was not committed")
	}
	assertNoBundleStaging(t, app)
}

func TestBundleCreationTimeCancellation(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data := readTestFile(t, path)
	ctx := &cancelBeforeRename{Context: context.Background()}
	if err := b.write(ctx, b.executable, []byte("uncommitted"), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Sys().(*syscall.Stat_t).Birthtimespec != after.Sys().(*syscall.Stat_t).Birthtimespec || !bytes.Equal(readTestFile(t, path), data) {
		t.Fatal("cancelled write changed the source")
	}
	assertNoBundleStaging(t, app)
}

func TestDryRunSkipsMetadataRestoration(t *testing.T) {
	for _, bundle := range []bool{false, true} {
		app := testBundle(t)
		path := filepath.Join(app, "Contents/MacOS/hello")
		if !bundle {
			app = t.TempDir()
			path = filepath.Join(app, "tool")
			if err := os.WriteFile(path, fixture(t, "unsigned-arm64"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if out, err := exec.Command("/bin/chmod", "+a", "everyone deny writeattr", path).CombinedOutput(); err != nil {
			t.Fatalf("ACL: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
		before := readTestFile(t, path)
		operand := path
		if bundle {
			operand = app
		}
		if err := Sign(context.Background(), operand, SignOptions{DryRun: true}); err != nil {
			t.Fatalf("dry-run metadata denial: %v", err)
		}
		if out, err := exec.Command("/usr/bin/codesign", "-fs", "-", "--dryrun", "--timestamp=none", operand).CombinedOutput(); err != nil {
			t.Fatalf("native dry-run metadata denial: %v: %s", err, out)
		}
		if !bytes.Equal(readTestFile(t, path), before) {
			t.Fatal("dry-run changed source")
		}
		if _, err := os.Stat(filepath.Join(app, bundleResourcesPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry-run wrote envelope: %v", err)
		}
		assertNoBundleStaging(t, app)
	}
}
