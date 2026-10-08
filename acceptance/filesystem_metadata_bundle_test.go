package acceptance

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// FAT bundles use ordinary files and directories. Symlink-dependent framework
// layouts remain in the native-filesystem suites; FAT cannot represent them.
type filesystemBundleResult struct {
	Filesystem, Profile, Location, Policy string
	Status                                int
	Stdout, Stderr                        string
	Archive, RootCarrier                  []byte
}

func filesystemBundleFixture(t *testing.T, bundle, profile, location string) {
	t.Helper()
	seeds := filesystemSeedInputs(t)
	infoCarrier := filepath.Join(bundle, "Contents/._Info.plist")
	if profile == "attribute-files" {
		// Restore metadata to the existing Info.plist before copying payloads.
		// Retain this entry: deleting it lets FAT reuse unrelated directory slots,
		// which changes the native first-error input across producer hosts.
		bundleWrite(t, bundle, "Contents/Info.plist", []byte(bundleInfo))
		installFilesystemCarrier(t, filepath.Join(bundle, "Contents/Info.plist"), seeds["ordinary"])
		bundleFixturePayload(t, bundle, "arm64")
	} else {
		bundleFixture(t, bundle, "arm64")
	}
	// Fixture creation can add process provenance. Start with the same data
	// forks on every producer before installing genuine captured metadata.
	// The bundle directory's own carrier lives beside it, outside WalkDir.
	if err := os.Remove(filepath.Join(filepath.Dir(bundle), "._"+filepath.Base(bundle))); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(bundle, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if profile == "attribute-files" && p == infoCarrier {
			return nil
		}
		if strings.HasPrefix(d.Name(), "._") && d.Type().IsRegular() {
			return os.Remove(p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if profile == "attribute-files" {
		installFilesystemCarrier(t, filepath.Join(bundle, "Contents"), seeds["ordinary"])
		if err := os.WriteFile(infoCarrier, seeds["ordinary"], 0600); err != nil {
			t.Fatal(err)
		}
		names := filesystemContentsOrder(t, bundle)
		info, resources, executable := slices.Index(names, "._Info.plist"), slices.Index(names, "Resources"), slices.Index(names, "MacOS")
		if info < 0 || resources < info || executable < info {
			t.Fatalf("metadata-before-payload fixture order changed: %q", names)
		}
	}
	target, seed := bundle, seeds["finder"]
	switch location {
	case "main":
		target, seed = filepath.Join(bundle, "Contents/MacOS/hello"), seeds["strip"]
	case "resource":
		target, seed = filepath.Join(bundle, "Contents/Resources/message.txt"), seeds["strip"]
	}
	installFilesystemCarrier(t, target, seed)
}

func observeFilesystemBundle(t *testing.T, executable, volume, filesystem, profile, location, policy string) filesystemBundleResult {
	t.Helper()
	bundle := filepath.Join(filesystemCaseDirectory(t, volume), "Fixture.app")
	filesystemBundleFixture(t, bundle, profile, location)
	args := []string{"-s", "-", "-i", "org.example.filesystem", "--timestamp=none"}
	want := 1
	if policy == "strip" {
		args = append(args, "--strip-disallowed-xattrs")
		if profile == "minimal" && location != "main" {
			want = 0
		}
	}
	out, diagnostic, status := run(t, executable, append(args, bundle)...)
	carrier, err := os.ReadFile(filepath.Join(filepath.Dir(bundle), "._Fixture.app"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	got := filesystemBundleResult{filesystem, profile, location, policy, status,
		strings.ReplaceAll(out, bundle, "$BUNDLE"), strings.ReplaceAll(diagnostic, bundle, "$BUNDLE"), layoutArchive(t, bundle), carrier}
	if status != want {
		t.Fatalf("status=%d want=%d: %s %s", status, want, out, diagnostic)
	}
	if status == 0 {
		mustRun(t, executable, "--verify", "--strict=sideband", bundle)
		if runtime.GOOS == "darwin" {
			mustRun(t, apple(t), "--verify", "--strict=sideband", bundle)
		}
	}
	return got
}

func filesystemBundleName(filesystem, profile, location, policy string) string {
	return "filesystem-bundle-" + filesystem + "-" + profile + "-" + location + "-" + policy + ".json"
}

func TestFilesystemMetadataBundles(t *testing.T) {
	for _, filesystem := range []string{"fat32", "exfat"} {
		t.Run(filesystem, func(t *testing.T) {
			volume := metadataVolume(t, filesystem)
			for _, profile := range []string{"minimal", "attribute-files"} {
				for _, location := range []string{"root", "main", "resource"} {
					for _, policy := range []string{"reject", "strip"} {
						t.Run(profile+"/"+location+"/"+policy, func(t *testing.T) {
							got := observeFilesystemBundle(t, binaryPath, volume, filesystem, profile, location, policy)
							if runtime.GOOS == "darwin" {
								want := observeFilesystemBundle(t, apple(t), volume, filesystem, profile, location, policy)
								if !reflect.DeepEqual(got, want) {
									attest(t, map[string]any{"go": got, "native": want})
									t.Fatalf("native bundle mismatch: status %d/%d diagnostic %q/%q archive %s/%s root carrier %s/%s", got.Status, want.Status, got.Stderr, want.Stderr, hash(got.Archive), hash(want.Archive), hash(got.RootCarrier), hash(want.RootCarrier))
								}
							}
							attest(t, got)
							if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
								wire, err := json.Marshal(got)
								if err != nil {
									t.Fatal(err)
								}
								bundleWrite(t, export, filesystemBundleName(filesystem, profile, location, policy), wire)
							}
						})
					}
				}
			}
		})
	}
}

func verifyImportedFilesystemBundles(t *testing.T, directory, reference string) {
	t.Helper()
	expected := map[string]filesystemBundleResult{}
	for _, filesystem := range []string{"fat32", "exfat"} {
		volume := metadataVolume(t, filesystem)
		for _, profile := range []string{"minimal", "attribute-files"} {
			for _, location := range []string{"root", "main", "resource"} {
				for _, policy := range []string{"reject", "strip"} {
					expected[filesystemBundleName(filesystem, profile, location, policy)] = observeFilesystemBundle(t, reference, volume, filesystem, profile, location, policy)
				}
			}
		}
	}
	seen := map[string]int{}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "filesystem-bundle-") {
			return nil
		}
		want, present := expected[entry.Name()]
		if !present {
			t.Fatal("unexpected foreign filesystem bundle artifact", path)
		}
		var got filesystemBundleResult
		if err := json.Unmarshal(nativeRead(t, path), &got); err != nil {
			return err
		}
		want.Stderr, err = foreignBundleDiagnostic(want.Stderr, foreignProducerOS(t, path))
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			attest(t, map[string]any{"artifact": path, "foreign": got, "native": want})
			t.Fatalf("%s: foreign outcome differs from native; archive %s/%s, diagnostic %q/%q", path, hash(got.Archive), hash(want.Archive), got.Stderr, want.Stderr)
		}
		seen[entry.Name()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if seen[name] != 2 {
			t.Fatal("expected both filesystem bundle producers", name, seen[name])
		}
	}
	attest(t, map[string]any{"native_cases": len(expected), "per_case_producers": seen})
}
