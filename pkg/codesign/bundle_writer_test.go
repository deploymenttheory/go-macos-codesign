package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertNoBundleStaging(t *testing.T, path string) {
	t.Helper()
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".apfs-replacement-") {
			t.Fatalf("staging leaked: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBundleReplacementCancellation(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	path := filepath.Join(app, b.executable)
	neighbour := filepath.Join(t.TempDir(), "neighbour")
	before := readTestFile(t, path)
	if err := os.Link(path, neighbour); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelBeforeRename{Context: context.Background()}
	if err := b.write(ctx, b.executable, []byte("uncommitted"), false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, p := range []string{path, neighbour} {
		if !bytes.Equal(readTestFile(t, p), before) {
			t.Fatal("cancelled write mutated", p)
		}
	}
	a, _ := os.Stat(path)
	other, _ := os.Stat(neighbour)
	if !os.SameFile(a, other) {
		t.Fatal("cancelled write detached link")
	}
	assertNoBundleStaging(t, app)
}

func TestBundleStagesAllExecutablesBeforeCommit(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	before := readTestFile(t, filepath.Join(app, b.executable))
	writes := []bundleWrite{
		{name: b.resourcesPath(), data: []byte("new resource envelope"), bundle: b, kind: bundleResourceWrite},
		{name: b.executable, data: []byte("first prepared executable"), bundle: b},
		{name: "missing-executable", data: []byte("invalid later executable"), bundle: b},
	}
	if err := commitBundleWrites(context.Background(), writes); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if !bytes.Equal(readTestFile(t, filepath.Join(app, b.executable)), before) {
		t.Fatal("committed before staging completed")
	}
	if _, err := b.root.Stat(b.base + "_CodeSignature"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("signature directory created: %v", err)
	}
	assertNoBundleStaging(t, app)
}

func TestBundleReplacementRejectsChangedTarget(t *testing.T) {
	for _, change := range []string{"replace", "remove"} {
		t.Run(change, func(t *testing.T) {
			app := testBundle(t)
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			p, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, data: []byte("new"), bundle: b}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer p.replacement.Close()
			// Retain the old inode so it cannot be recycled into the changed target.
			if err := b.root.Link(b.executable, "old-inode"); err != nil {
				t.Fatal(err)
			}
			if err := b.root.Remove(b.executable); err != nil {
				t.Fatal(err)
			}
			if change == "replace" {
				if err := b.root.WriteFile(b.executable, []byte("replacement by another writer"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.commit(context.Background()); err == nil {
				t.Fatal("committed to a changed target")
			}
			if change == "replace" && string(readTestFile(t, filepath.Join(app, b.executable))) != "replacement by another writer" {
				t.Fatal("changed target overwritten")
			}
			if err := p.replacement.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoBundleStaging(t, app)
		})
	}
}

func TestBundleLaterCommitFailureRetainsEarlierCommit(t *testing.T) {
	app := testBundle(t)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	neighbour := filepath.Join(t.TempDir(), "neighbour")
	path := filepath.Join(app, b.executable)
	before := readTestFile(t, path)
	if err := os.Link(path, neighbour); err != nil {
		t.Fatal(err)
	}
	writes := []bundleWrite{{name: b.executable, data: []byte("committed first"), bundle: b}, {name: "Contents", data: []byte("cannot overwrite directory"), bundle: b, kind: bundleResourceWrite}}
	if err := commitBundleWrites(context.Background(), writes); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if string(readTestFile(t, path)) != "committed first" || !bytes.Equal(readTestFile(t, neighbour), before) {
		t.Fatal("incorrect partial-commit state")
	}
	assertNoBundleStaging(t, app)
}

func TestBundleCommittedAccessRejectsChangedTarget(t *testing.T) {
	for _, change := range []string{"replace", "remove", "symlink", "closed-root"} {
		t.Run(change, func(t *testing.T) {
			app := testBundle(t)
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			p, err := prepareBundleExecutable(context.Background(), bundleWrite{name: b.executable, data: []byte("committed"), bundle: b}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer p.replacement.Close()
			if err := p.commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := p.replacement.Close(); err != nil {
				t.Fatal(err)
			}
			if change == "closed-root" {
				if err := b.root.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := b.root.Link(b.executable, "committed-inode"); err != nil {
					t.Fatal(err)
				}
				if err := b.root.Remove(b.executable); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "replace":
					if err := b.root.WriteFile(b.executable, []byte("changed target"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := b.root.Symlink("../../committed-inode", b.executable); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := p.recordReadAccess(); err == nil {
				t.Fatal("recorded access through a changed target")
			}
			if change == "replace" && string(readTestFile(t, filepath.Join(app, b.executable))) != "changed target" {
				t.Fatal("changed target modified")
			}
			assertNoBundleStaging(t, app)
		})
	}
}
