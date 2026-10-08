package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func nativeSigningProfile(t *testing.T) osversion.MacOSProfile {
	t.Helper()
	apple(t)
	version, err := osversion.Detect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// Sweep every allocation-alignment residue on both architectures, with native
// defaults and explicit page sizes. Full byte equality includes the padding,
// patched load commands, special slots, CodeDirectory and page digests.
func TestNativeSigningProfiles(t *testing.T) {
	profile := nativeSigningProfile(t)
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, page := range []uint32{0, 4096, 16384} {
			for length := 1; length <= 16; length++ {
				t.Run(fmt.Sprintf("%s/%d/%d", arch, page, length), func(t *testing.T) {
					input := nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch))
					identifier := "org.example." + strings.Repeat("x", length)
					file := filepath.Join(t.TempDir(), "fixture")
					if err := os.WriteFile(file, input, 0700); err != nil {
						t.Fatal(err)
					}
					args := []string{"-s", "-", "-i", identifier, "--timestamp=none"}
					if page != 0 {
						args = append(args, "--pagesize", fmt.Sprint(page))
					}
					mustRun(t, apple(t), append(args, file)...)
					want := nativeRead(t, file)
					got, err := codesign.SignBytes(t.Context(), input, codesign.SignOptions{MacOSProfile: profile, Identifier: identifier, PageSize: page})
					if err != nil {
						t.Fatal(err)
					}
					nativeEqual(t, "versioned native signature", got, want)
					if _, err = codesign.VerifyBytes(t.Context(), got, codesign.VerifyOptions{}); err != nil {
						t.Fatal(err)
					}
					attest(t, map[string]any{"profile": profile, "architecture": arch, "page_size": page, "identifier": identifier, "native_sha256": hash(want), "complete_bytes_equal": true})
				})
			}
		}
	}
}

// Isolate scheduling as a possible cause of the competing-error difference.
// This retains both native default and explicitly serial observations instead
// of forcing serial flags into the ordinary CLI parity suite.
func TestNativeSigningProfileResourceOrder(t *testing.T) {
	profile := nativeSigningProfile(t)
	probe := resourceOrderProbe(t)
	for _, filesystem := range []string{"fat32", "exfat"} {
		t.Run(filesystem, func(t *testing.T) {
			volume := metadataVolume(t, filesystem)
			for _, serial := range []bool{false, true} {
				for repeat := 0; repeat < 3; repeat++ {
					t.Run(fmt.Sprintf("serial-%v/%d", serial, repeat), func(t *testing.T) {
						bundle := filepath.Join(filesystemCaseDirectory(t, volume), "Fixture.app")
						filesystemBundleFixture(t, bundle, "attribute-files", "resource")
						before := layoutArchive(t, bundle)
						trace, want := observeResourceOrder(t, probe, bundle)
						args := []string{"-s", "-", "-i", "org.example.filesystem", "--timestamp=none"}
						if serial {
							args = append(args, "--single-threaded-signing")
						}
						out, diagnostic, status := run(t, apple(t), append(args, bundle)...)
						diagnostic = strings.ReplaceAll(diagnostic, bundle, "$BUNDLE")
						attest(t, map[string]any{"fts_trace": trace, "profile": profile, "serial": serial, "repeat": repeat, "status": status, "stdout": out, "stderr": diagnostic, "before_sha256": hash(before), "after_sha256": hash(layoutArchive(t, bundle))})
						if status != 1 || out != "" || diagnostic != want {
							t.Fatalf("native resource ordering changed: %d %q %q", status, out, diagnostic)
						}
						nativeEqual(t, "failed signing preserves data forks", layoutArchive(t, bundle), before)
					})
				}
			}
		})
	}
}
