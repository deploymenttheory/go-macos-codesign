package codesign

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// These complete native archives were retained from the failed macOS15/26 CI
// jobs. Comparing the entire executable catches allocation, command and code
// hash differences; ignoring zero padding would hide the original regression.
func TestSigningProfileNativeArchives(t *testing.T) {
	for _, major := range []osversion.MacOSProfile{osversion.MacOS15, osversion.MacOS26} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			wire, err := os.ReadFile(fmt.Sprintf("../../testdata/filesystem-metadata/profiles/macos-%d.json", major))
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				Profile    osversion.MacOSProfile `json:"profile"`
				Provenance struct {
					Host    string            `json:"host"`
					Sources map[string]string `json:"source_sha256"`
				} `json:"seed_provenance"`
				Cases []struct {
					Test   string
					Native struct {
						Status  int
						Archive []byte
					}
				}
			}
			if err = json.Unmarshal(wire, &capture); err != nil {
				t.Fatal(err)
			}
			if capture.Profile != major || len(capture.Cases) != 6 {
				t.Fatal("incomplete native profile", capture.Profile, len(capture.Cases))
			}
			version, err := osversion.ParseProductVersion(capture.Provenance.Host)
			if err != nil || version.Major != uint32(major) {
				t.Fatal("wrong native producer", version, err)
			}
			for _, arch := range []string{"arm64", "x86_64"} {
				ast, err := os.ReadFile(fmt.Sprintf("../../testdata/filesystem-metadata/profiles/macos-%d-%s.ast.json.gz", major, arch))
				if err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%x", sha256.Sum256(ast)) != capture.Provenance.Sources["seed-"+arch+".ast.json.gz"] {
					t.Fatal("changed native producer AST", arch)
				}
			}
			signed := 0
			for _, row := range capture.Cases {
				if row.Native.Status != 0 {
					continue
				}
				signed++
				t.Run(row.Test, func(t *testing.T) {
					files := map[string][]byte{}
					reader := tar.NewReader(bytes.NewReader(row.Native.Archive))
					for {
						header, err := reader.Next()
						if errors.Is(err, io.EOF) {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						data, err := io.ReadAll(reader)
						if err != nil {
							t.Fatal(err)
						}
						files[header.Name] = data
					}
					opts := SignOptions{MacOSProfile: major, Identifier: "org.example.filesystem", InfoPlist: files["Contents/Info.plist"], Resources: files["Contents/_CodeSignature/CodeResources"]}
					want := files["Contents/MacOS/hello"]
					if len(opts.InfoPlist) == 0 || len(opts.Resources) == 0 || len(want) == 0 {
						t.Fatal("incomplete native archive")
					}
					got, err := SignBytes(t.Context(), fixture(t, "unsigned-arm64"), opts)
					if err != nil {
						t.Fatal(err)
					}
					assertAppleBytes(t, got, want)
					if _, err = VerifyBytes(t.Context(), got, VerifyOptions{InfoPlist: opts.InfoPlist, Resources: opts.Resources}); err != nil {
						t.Fatal(err)
					}
				})
			}
			if signed != 4 {
				t.Fatal("missing native signed archives", signed)
			}
		})
	}
}

func TestSigningProfiles(t *testing.T) {
	input := fixture(t, "unsigned-arm64")
	baseline, err := SignBytes(t.Context(), input, SignOptions{Identifier: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []osversion.MacOSProfile{0, osversion.MacOS15, osversion.MacOS26, osversion.MacOS27} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			got, err := SignBytes(t.Context(), input, SignOptions{Identifier: "profile", MacOSProfile: profile})
			if err != nil {
				t.Fatal(err)
			}
			if (profile == 0 || profile == osversion.MacOS27) && !bytes.Equal(got, baseline) {
				t.Fatal("reference default changed")
			}
			if _, err = VerifyBytes(t.Context(), got, VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
			app := testBundle(t)
			bundleFile(t, app, "Contents/Resources/message.txt", []byte("resource"))
			opts := SignOptions{MacOSProfile: profile, AppleDoubleFiles: map[string]appledouble.Value{"Contents/Resources/message.txt": sidebandCarrier(t, appledouble.File{ResourceFork: []byte("fork")})}}
			err = Sign(t.Context(), app, opts)
			var metadata *signingMetadataError
			if !errors.As(err, &metadata) {
				t.Fatal("missing resource preflight failure", err)
			}
		})
	}
	opts := SignOptions{Identifier: "profile", MacOSProfile: 99}
	if _, err = SignBytes(t.Context(), input, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err = Sign(t.Context(), "missing", opts); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
