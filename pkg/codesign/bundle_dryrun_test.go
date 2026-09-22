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

type cancelDuringDryRunAllocation struct {
	context.Context
	directory string
	cancelled bool
}

func (c *cancelDuringDryRunAllocation) Err() error {
	entries, err := os.ReadDir(c.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".apfs-replacement-") {
			c.cancelled = true
		}
	}
	if c.cancelled {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestUnsignedNestedDryRunAllocation(t *testing.T) {
	for _, shape := range []string{"helper", "child", "grandchild"} {
		for _, operation := range []string{"deep", "denied", "shallow-denied", "cancelled"} {
			t.Run(shape+"/"+operation, func(t *testing.T) {
				app := testBundle(t)
				apps := []string{app}
				paths := []string{filepath.Join(app, "Contents/MacOS/hello")}
				if shape == "helper" {
					bundleFile(t, app, "Contents/Helpers/tool", fixture(t, "unsigned-arm64"))
					paths = append(paths, filepath.Join(app, "Contents/Helpers/tool"))
				} else {
					child := nestedApp(t, app, "Contents/PlugIns/Child.app")
					apps = append(apps, child)
					paths = append(paths, filepath.Join(child, "Contents/MacOS/hello"))
					if shape == "grandchild" {
						grand := nestedApp(t, child, "Contents/PlugIns/Grand.app")
						apps = append(apps, grand)
						paths = append(paths, filepath.Join(grand, "Contents/MacOS/hello"))
					}
				}
				before := make([]os.FileInfo, len(paths))
				for i, path := range paths {
					var err error
					before[i], err = os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				ctx := context.Background()
				opts := SignOptions{Deep: true, DryRun: true}
				want := ErrUnsigned
				directory := filepath.Dir(paths[len(paths)-1])
				var cancel *cancelDuringDryRunAllocation
				switch operation {
				case "denied", "shallow-denied":
					denyExecutableDirectoryCreation(t, directory)
					if operation == "denied" {
						want = os.ErrPermission
					} else {
						opts.Deep = false
					}
				case "cancelled":
					cancel = &cancelDuringDryRunAllocation{Context: ctx, directory: directory}
					ctx, want = cancel, context.Canceled
				}
				err := Sign(ctx, app, opts)
				if !errors.Is(err, want) {
					t.Fatalf("want %v, got %v", want, err)
				}
				if !errors.Is(want, ErrUnsigned) && errors.Is(err, ErrUnsigned) {
					t.Fatal("seal error masked earlier allocation failure")
				}
				if cancel != nil && !cancel.cancelled {
					t.Fatal("allocation did not reach cancellation boundary")
				}
				for i, path := range paths {
					after, err := os.Stat(path)
					if err != nil || !os.SameFile(before[i], after) || !before[i].ModTime().Equal(after.ModTime()) {
						t.Fatal("dry run changed executable", err)
					}
					if !bytes.Equal(readTestFile(t, path), fixture(t, "unsigned-arm64")) {
						t.Fatal("dry run changed executable bytes")
					}
				}
				for _, bundle := range apps {
					if _, err := os.Stat(filepath.Join(bundle, "Contents/_CodeSignature")); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("dry run created envelope directory", err)
					}
				}
				assertNoBundleStaging(t, app)
			})
		}
	}
}
