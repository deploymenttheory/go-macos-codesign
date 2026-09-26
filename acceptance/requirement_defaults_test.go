package acceptance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func defaultRequirementInput(t *testing.T, profile string) ([]byte, string, string) {
	t.Helper()
	if profile == "none" {
		return nil, "", "none"
	}
	if profile == "empty" {
		return []byte{0xfa, 0xde, 0x0c, 1, 0, 0, 0, 12, 0, 0, 0, 0}, "", "binary"
	}
	source := map[string]string{"host": "host => never", "partial": "host => never guest => never library => never plugin => never", "override": "host => never designated => always", "never": "host => never designated => never", "unordered": "host => never plugin => never"}[profile]
	data, err := codesign.CompileRequirements(source)
	if err != nil {
		t.Fatal(err)
	}
	form := "binary"
	if profile == "host" || profile == "never" {
		form = "inline"
	}
	if profile == "partial" {
		form = "source"
	}
	if profile == "unordered" {
		first := bytes.Clone(data[12:20])
		copy(data[12:20], data[20:28])
		copy(data[20:28], first)
	}
	return data, source, form
}

func TestRequirementDefaultChains(t *testing.T) {
	keychain := ""
	if runtime.GOOS == "darwin" {
		keychain = nativeChainKeychain(t)
	}
	for _, profile := range []string{"root", "intermediate", "leaf"} {
		t.Run(profile, func(t *testing.T) {
			dir := extractionDirectory(t)
			portable := defaultFixture(t, filepath.Join(dir, "go"), "arm64")
			identity := filepath.Join(root, "testdata/chains", profile+"-identity.pem")
			args := []string{"-i", "org.example.defaults", "--timestamp=none", "-r=host => never"}
			mustRun(t, binaryPath, append(append([]string{"-s", identity}, args...), portable)...)
			mustRun(t, binaryPath, "--verify", "--trust-root", filepath.Join(root, "testdata/chains", profile+"-root.pem"), portable)
			r, _ := inspectDefaults(t, portable)
			if runtime.GOOS == "darwin" {
				native := defaultFixture(t, filepath.Join(dir, "apple"), "arm64")
				mustRun(t, apple(t), append(append([]string{"--keychain", keychain, "-s", "leaf-" + profile}, args...), native)...)
				compareDefaultComponents(t, portable, native)
				mustRun(t, apple(t), "--verify", "--strict", portable)
			}
			attest(t, map[string]any{"organization_anchor": profile, "requirements_sha256": hash(signatureBlob(r.Architectures[0].Signature, codesign.SlotRequirements)), "directory_sha256": hash(r.Architectures[0].Signature.Directories[0].Raw), "portable_ca_verified": true, "native_compared": runtime.GOOS == "darwin"})
		})
	}
}

func defaultComponents(t *testing.T, path string) []byte {
	t.Helper()
	r, _ := inspectDefaults(t, path)
	var data []byte
	for _, a := range r.Architectures {
		data = append(data, signatureBlob(a.Signature, codesign.SlotRequirements)...)
		data = append(data, a.Signature.Directories[0].Raw...)
	}
	return data
}

func TestRequirementDefaultLifecycle(t *testing.T) {
	for _, algorithm := range []string{"adhoc", "rsa"} {
		t.Run(algorithm, func(t *testing.T) {
			identity, keychain := "-", ""
			var id *codesign.Identity
			if algorithm == "rsa" {
				identity = filepath.Join(root, "testdata/identities/rsa-identity.pem")
				var err error
				id, err = codesign.LoadIdentityPEM(nativeRead(t, identity), nil)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS == "darwin" {
					keychain = nativeTestKeychain(t, "rsa")
				}
			}
			for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
				modes := []string{"replace-default", "replace-empty", "replace-partial", "malformed"}
				if format != "dmg" {
					modes = append(modes, "dryrun")
				}
				for _, mode := range modes {
					t.Run(format+"/"+mode, func(t *testing.T) {
						dir := extractionDirectory(t)
						t.Chdir(dir)
						initial, err := codesign.CompileRequirements("host => never designated => always")
						if err != nil {
							t.Fatal(err)
						}
						args := []string{"-f", "-i", "org.example.new", "--timestamp=none"}
						switch mode {
						case "replace-empty":
							empty, _, _ := defaultRequirementInput(t, "empty")
							if err := os.WriteFile("requirements", empty, 0644); err != nil {
								t.Fatal(err)
							}
							args = append(args, "-r", "requirements")
						case "replace-partial", "dryrun":
							args = append(args, "-r=plugin => never")
							if mode == "dryrun" {
								args = append(args, "--dryrun")
							}
						case "malformed":
							args = append(args, "-r=host = > always")
						}
						programs := []string{binaryPath}
						if runtime.GOOS == "darwin" {
							programs = append(programs, apple(t))
						}
						var goBefore, goAfter, goComponents []byte
						var goOut, goErr, nativeErr string
						for index, exe := range programs {
							workspace := filepath.Join(dir, "fixture")
							if err := os.RemoveAll(workspace); err != nil {
								t.Fatal(err)
							}
							path := defaultFixture(t, workspace, format)
							if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Identifier: "org.example.old", Identity: id, Requirements: initial, SigningTime: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}); err != nil {
								t.Fatal(err)
							}
							before := layoutArchive(t, workspace)
							signer := []string{"-s", identity}
							if index == 1 && id != nil {
								signer = []string{"--keychain", keychain, "-s", "Public codesign test identity rsa"}
							}
							out, stderr, status := run(t, exe, append(append(signer, args...), path)...)
							want := 0
							if mode == "malformed" {
								want = 1
							}
							if status != want {
								t.Fatal(status, stderr)
							}
							after := layoutArchive(t, workspace)
							components := defaultComponents(t, path)
							if mode == "malformed" || mode == "dryrun" {
								nativeEqual(t, "preserved signature tree", after, before)
							} else {
								r, _ := inspectDefaults(t, path)
								text, err := r.RequirementText("")
								if err != nil {
									t.Fatal(err)
								}
								if strings.Contains(string(text), "host =>") || strings.Contains(string(text), "designated => always") {
									t.Fatal("old requirements leaked", string(text))
								}
								verify := codesign.VerifyOptions{}
								if id != nil {
									verify.TrustedCertificates = id.Certificates
								}
								if _, err := codesign.Verify(context.Background(), path, verify); err != nil {
									t.Fatal(err)
								}
								if runtime.GOOS == "darwin" {
									mustRun(t, apple(t), "--verify", "--strict", path)
								}
							}
							if index == 0 {
								goBefore, goAfter, goComponents = before, after, components
								goOut, goErr = out, stderr
							} else {
								nativeErr = stderr
								nativeEqual(t, "same original tree", before, goBefore)
								nativeEqual(t, "result requirement/directory bytes", components, goComponents)
								if mode != "malformed" {
									nativeEqual(t, "stdout", []byte(out), []byte(goOut))
									nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
								}
								if id == nil || mode == "malformed" || mode == "dryrun" {
									nativeEqual(t, "result complete tree", after, goAfter)
								}
							}
						}
						preserved := mode == "malformed" || mode == "dryrun"
						attest(t, map[string]any{"algorithm": algorithm, "format": format, "mode": mode, "input_sha256": hash(goBefore), "components_sha256": hash(goComponents), "input_preserved": preserved, "native_compared": len(programs) == 2, "exact_diagnostics": mode != "malformed", "stderr": goErr, "native_stderr": nativeErr})
					})
				}
			}
		})
	}
}

func defaultFixture(t *testing.T, dir, format string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "input")
	switch format {
	case "app":
		path = filepath.Join(dir, "Example.app")
		bundleFixture(t, path, "arm64")
	case "framework":
		path = layoutFixture(t, dir, "versioned", "arm64", "binary")
		// The outer-set matrix signs shallowly; preserve an independently
		// valid helper so a false outer DR does not become a child-seal test.
		if err := codesign.Sign(context.Background(), filepath.Join(path, "Versions/A/helper"), codesign.SignOptions{Identifier: "org.example.helper"}); err != nil {
			t.Fatal(err)
		}
	default:
		var data []byte
		if format == "dmg" {
			data = dmgFixture(t, "zlib")
		} else {
			data = nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+format))
		}
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func inspectDefaults(t *testing.T, path string) (*codesign.Report, []byte) {
	t.Helper()
	report, err := codesign.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	executable := path
	if report.Bundle != nil {
		executable = report.Bundle.Executable
	}
	return report, nativeRead(t, executable)
}

func compareDefaultComponents(t *testing.T, portable, native string) {
	t.Helper()
	got, goBytes := inspectDefaults(t, portable)
	want, nativeBytes := inspectDefaults(t, native)
	if len(got.Architectures) != len(want.Architectures) {
		t.Fatal("architecture count")
	}
	for i, ga := range got.Architectures {
		na := want.Architectures[i]
		if ga.Name != na.Name || ga.Offset != na.Offset || ga.SignatureOffset != na.SignatureOffset {
			t.Fatal("code layout differs")
		}
		nativeEqual(t, "code/payload bytes", goBytes[ga.Offset:ga.Offset+ga.SignatureOffset], nativeBytes[na.Offset:na.Offset+na.SignatureOffset])
		if len(ga.Signature.Blobs) != len(na.Signature.Blobs) {
			t.Fatal("component count")
		}
		for _, b := range na.Signature.Blobs {
			if b.Slot != codesign.SlotCMS {
				nativeEqual(t, fmt.Sprintf("component %d", b.Slot), signatureBlob(ga.Signature, b.Slot), b.Data)
			}
		}
	}
	text, err := got.RequirementText("")
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, status := run(t, apple(t), "-d", "-r-", native)
	if status != 0 {
		t.Fatal(status, stderr)
	}
	nativeEqual(t, "extracted requirement text", text, []byte(out))
}

func TestRequirementDefaultSigning(t *testing.T) {
	for _, algorithm := range []string{"adhoc", "rsa", "p256", "p384", "p521"} {
		t.Run(algorithm, func(t *testing.T) {
			identity := "-"
			var id *codesign.Identity
			keychain := ""
			if algorithm != "adhoc" {
				identity = filepath.Join(root, "testdata/identities", algorithm+"-identity.pem")
				var err error
				id, err = codesign.LoadIdentityPEM(nativeRead(t, identity), nil)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS == "darwin" {
					keychain = nativeTestKeychain(t, algorithm)
				}
			}
			for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
				for _, profile := range []string{"none", "empty", "host", "partial", "override", "never", "unordered"} {
					t.Run(format+"/"+profile, func(t *testing.T) {
						dir := extractionDirectory(t)
						portable := defaultFixture(t, filepath.Join(dir, "go"), format)
						inputHash := hash(layoutArchive(t, filepath.Join(dir, "go")))
						given, source, form := defaultRequirementInput(t, profile)
						args := []string{"-i", "org.example.defaults", "--timestamp=none"}
						if form != "none" {
							argument := "=" + source
							if form != "inline" {
								argument = filepath.Join(dir, "requirements")
								data := given
								if form == "source" {
									data = []byte(source)
								}
								if err := os.WriteFile(argument, data, 0644); err != nil {
									t.Fatal(err)
								}
							}
							args = append(args, "-r", argument)
						}
						mustRun(t, binaryPath, append(append([]string{"-s", identity}, args...), portable)...)
						verify := codesign.VerifyOptions{}
						if id != nil {
							verify.TrustedCertificates = id.Certificates
						}
						_, err := codesign.Verify(context.Background(), portable, verify)
						knownDifference := profile == "never"
						if knownDifference {
							if !errors.Is(err, codesign.ErrDesignatedRequirement) {
								t.Fatal("explicit verification policy", err)
							}
						} else if err != nil {
							t.Fatal(err)
						}
						report, _ := inspectDefaults(t, portable)
						var reqHashes, cdHashes []string
						for _, arch := range report.Architectures {
							set := signatureBlob(arch.Signature, codesign.SlotRequirements)
							reqHashes = append(reqHashes, hash(set))
							cdHashes = append(cdHashes, hash(arch.Signature.Directories[0].Raw))
							count := binary.BigEndian.Uint32(set[8:])
							expected := uint32(0)
							if given != nil {
								expected = binary.BigEndian.Uint32(given[8:])
							}
							if id != nil && profile != "override" && profile != "never" {
								expected++
							}
							if count != expected {
								t.Fatal("merged entry count", count, expected)
							}
						}
						text, err := report.RequirementText("")
						if err != nil {
							t.Fatal(err)
						}
						if runtime.GOOS == "darwin" {
							native := defaultFixture(t, filepath.Join(dir, "apple"), format)
							nativeArgs := []string{"-s", "-"}
							if id != nil {
								nativeArgs = []string{"--keychain", keychain, "-s", "Public codesign test identity " + algorithm}
							}
							mustRun(t, apple(t), append(append(nativeArgs, args...), native)...)
							compareDefaultComponents(t, portable, native)
							mustRun(t, apple(t), "--verify", "--strict", native)
							mustRun(t, apple(t), "--verify", "--strict", portable)
							if id == nil {
								nativeEqual(t, "complete ad-hoc tree", layoutArchive(t, filepath.Join(dir, "go")), layoutArchive(t, filepath.Join(dir, "apple")))
							}
						}
						attest(t, map[string]any{"algorithm": algorithm, "format": format, "profile": profile, "input_form": form, "input_sha256": inputHash, "supplied_sha256": hash(given), "requirements_sha256": reqHashes, "directories_sha256": cdHashes, "text_sha256": hash(text), "native_compared": runtime.GOOS == "darwin", "native_strict_verified": runtime.GOOS == "darwin", "native_components_equal": runtime.GOOS == "darwin", "portable_verified": !knownDifference, "known_self_requirement_verification_difference": knownDifference})
					})
				}
			}
		})
	}
}

func TestRequirementDefaultNested(t *testing.T) {
	for _, algorithm := range []string{"adhoc", "rsa"} {
		t.Run(algorithm, func(t *testing.T) {
			identity, keychain := "-", ""
			if algorithm == "rsa" {
				identity = filepath.Join(root, "testdata/identities/rsa-identity.pem")
				if runtime.GOOS == "darwin" {
					keychain = nativeTestKeychain(t, "rsa")
				}
			}
			for _, arch := range []string{"arm64", "x86_64", "universal"} {
				t.Run(arch, func(t *testing.T) {
					dir := extractionDirectory(t)
					portable := filepath.Join(dir, "go", "Example.app")
					recursiveFixture(t, portable, arch, "mixed")
					args := []string{"--deep", "--timestamp=none", "-r=host => never"}
					mustRun(t, binaryPath, append(append([]string{"-s", identity}, args...), portable)...)
					verify := []string{"--verify", "--deep"}
					if algorithm == "rsa" {
						verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/rsa-cert.pem"))
					}
					mustRun(t, binaryPath, append(verify, portable)...)
					members := append([]string(nil), recursiveApps...)
					for _, helper := range nestedHelpers {
						members = append(members, filepath.Join(recursiveApps[2], helper))
					}
					var hashes []string
					for _, rel := range members {
						r, _ := inspectDefaults(t, filepath.Join(portable, filepath.FromSlash(rel)))
						for _, a := range r.Architectures {
							hashes = append(hashes, hash(signatureBlob(a.Signature, codesign.SlotRequirements)), hash(a.Signature.Directories[0].Raw))
						}
						text, err := r.RequirementText("")
						if err != nil {
							t.Fatal(err)
						}
						if algorithm == "rsa" && !strings.Contains(string(text), "designated => identifier ") {
							t.Fatal("child default missing")
						}
					}
					if runtime.GOOS == "darwin" {
						native := filepath.Join(dir, "apple", "Example.app")
						recursiveFixture(t, native, arch, "mixed")
						nativeArgs := []string{"-s", "-"}
						if algorithm == "rsa" {
							nativeArgs = []string{"--keychain", keychain, "-s", "Public codesign test identity rsa"}
						}
						mustRun(t, apple(t), append(append(nativeArgs, args...), native)...)
						for _, rel := range members {
							compareDefaultComponents(t, filepath.Join(portable, filepath.FromSlash(rel)), filepath.Join(native, filepath.FromSlash(rel)))
						}
						mustRun(t, apple(t), "--verify", "--strict", "--deep", portable)
					}
					attest(t, map[string]any{"algorithm": algorithm, "architecture": arch, "members": len(members), "component_sha256": hashes, "portable_deep_verified": true, "native_compared": runtime.GOOS == "darwin", "native_deep_verified": runtime.GOOS == "darwin"})
				})
			}
		})
	}
}
