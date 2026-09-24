package codesign

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleDirectoryParentAndSuffixes(t *testing.T) {
	app := testBundle(t)
	dir, err := filepath.EvalSymlinks(filepath.Dir(app))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	name := filepath.Base(app)
	if err := os.Symlink(".", "parent"); err != nil {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), name, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, operand := range []string{name, name + string(filepath.Separator), name + string(filepath.Separator) + ".", filepath.Join("parent", name)} {
		r, err := Inspect(context.Background(), operand)
		if err != nil {
			t.Fatal(operand, err)
		}
		executable, err := filepath.Abs(r.Bundle.Executable)
		if err != nil || executable != filepath.Join(dir, name, "Contents/MacOS/hello") {
			t.Fatal(operand, executable, err)
		}
	}
	// Resolving a volume root must retain its separator (including Windows).
	volume := filepath.VolumeName(dir) + string(filepath.Separator)
	if got, err := resolveBundleDirectory(volume); err != nil || got != volume {
		t.Fatal("volume root", got, err)
	}
	if _, err := resolveBundleDirectory(filepath.Join("missing", name)); err == nil {
		t.Fatal("accepted missing parent")
	}
	if err := os.Symlink(name, "Final.app"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", string(filepath.Separator), string(filepath.Separator) + "."} {
		if _, err := Inspect(context.Background(), "Final.app"+suffix); err == nil {
			t.Fatal("accepted unsupported final root alias", suffix)
		}
	}
}
