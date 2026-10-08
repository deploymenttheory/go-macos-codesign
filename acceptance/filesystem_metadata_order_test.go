package acceptance

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// These are two real creation sequences: copy resource data before metadata,
// or restore Info.plist's packed metadata before copying the remaining tree.
// The resulting bytes are identical; directory enumeration is part of the input.
func orderedFilesystemBundle(t *testing.T, bundle, order string) []string {
	t.Helper()
	seeds := filesystemSeedInputs(t)
	infoCarrier := filepath.Join(bundle, "Contents/._Info.plist")
	if order == "resource-first" {
		bundleWrite(t, bundle, "Contents/Resources/message.txt", []byte("hello\n"))
	} else {
		bundleWrite(t, bundle, "Contents/._Info.plist", seeds["ordinary"])
	}
	bundleFixture(t, bundle, "arm64")
	// Keep the deliberately early entry throughout preparation. The ordinary
	// fixture removes and recreates attribute files, which lets FAT allocation
	// move this entry after Resources on Windows and macOS 26. Overwrite its
	// contents in place after removing incidental process metadata instead.
	if err := filepath.WalkDir(bundle, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if order == "nested-first" && path == infoCarrier {
			return nil
		}
		if strings.HasPrefix(entry.Name(), "._") && entry.Type().IsRegular() {
			return os.Remove(path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	installFilesystemCarrier(t, filepath.Join(bundle, "Contents"), seeds["ordinary"])
	if err := os.WriteFile(infoCarrier, seeds["ordinary"], 0600); err != nil {
		t.Fatal(err)
	}
	installFilesystemCarrier(t, filepath.Join(bundle, "Contents/Resources/message.txt"), seeds["strip"])
	directory, err := os.Open(filepath.Join(bundle, "Contents"))
	if err != nil {
		t.Fatal(err)
	}
	names, err := directory.Readdirnames(-1)
	closed := directory.Close()
	if err != nil || closed != nil {
		t.Fatal(err, closed)
	}
	nested, resource := slices.Index(names, "._Info.plist"), slices.Index(names, "Resources")
	if nested < 0 || resource < 0 || (resource < nested) != (order == "resource-first") {
		t.Fatalf("fixture did not establish %s: %q", order, names)
	}
	return names
}

func TestFilesystemMetadataResourceOrder(t *testing.T) {
	probe := ""
	if runtime.GOOS == "darwin" {
		probe = resourceOrderProbe(t)
	}
	for _, filesystem := range []string{"fat32", "exfat"} {
		t.Run(filesystem, func(t *testing.T) {
			volume := metadataVolume(t, filesystem)
			var contentsAcrossOrders []byte
			for _, order := range []string{"resource-first", "nested-first"} {
				t.Run(order, func(t *testing.T) {
					tools := []string{binaryPath}
					if runtime.GOOS == "darwin" {
						tools = append(tools, apple(t))
					}
					results := []map[string]any{}
					var baseline []byte
					for _, tool := range tools {
						bundle := filepath.Join(filesystemCaseDirectory(t, volume), "Fixture.app")
						names := orderedFilesystemBundle(t, bundle, order)
						before := layoutArchive(t, bundle)
						if contentsAcrossOrders == nil {
							contentsAcrossOrders = before
						} else {
							nativeEqual(t, "creation orders have identical archived contents", before, contentsAcrossOrders)
						}
						if baseline != nil {
							nativeEqual(t, "identical native and Go input bytes", before, baseline)
						} else {
							baseline = before
						}
						want := "$BUNDLE: resource fork, Finder information, or similar detritus not allowed\n"
						if order == "nested-first" {
							want = "$BUNDLE: code object is not signed at all\nIn subcomponent: $BUNDLE/Contents/._Info.plist\n"
						}
						var trace []resourceOrderEntry
						if probe != "" {
							var predicted string
							trace, predicted = observeResourceOrder(t, probe, bundle)
							if predicted != want {
								t.Fatal("native FTS order differs from fixture's directory order", predicted, want)
							}
						}
						out, diagnostic, status := run(t, tool, "-s", "-", "-i", "org.example.filesystem", "--timestamp=none", bundle)
						diagnostic = strings.ReplaceAll(diagnostic, bundle, "$BUNDLE")
						if status != 1 || out != "" || diagnostic != want {
							t.Fatalf("%s: status=%d stdout=%q diagnostic=%q want=%q", tool, status, out, diagnostic, want)
						}
						nativeEqual(t, "failure leaves complete data-fork tree unchanged", layoutArchive(t, bundle), before)
						results = append(results, map[string]any{"native": tool != binaryPath, "directory_order": names, "fts_trace": trace, "status": status, "stdout": out, "stderr": diagnostic, "archive": before})
					}
					attest(t, map[string]any{"filesystem": filesystem, "creation_order": order, "results": results})
				})
			}
		})
	}
}
