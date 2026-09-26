package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func requirementInput(t *testing.T, dir, format, profile string) string {
	t.Helper()
	id := "adhoc"
	if profile == "rsa" || profile == "chain" {
		id = profile
	}
	if profile == "implicit-rsa" {
		id = "rsa"
	}
	path, _ := certificateExtractionInput(t, dir, format, id)
	if profile == "implicit" || profile == "rsa" || profile == "chain" {
		return path
	}
	var identity *codesign.Identity
	if id != "adhoc" {
		var err error
		identity, err = codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities", id+"-identity.pem")), nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := codesign.CompileRequirements(`identifier "org.example.extract" and (always or ! never)`)
	if err != nil {
		t.Fatal(err)
	}
	switch profile {
	case "implicit-rsa":
		req = []byte{0xfa, 0xde, 0x0c, 1, 0, 0, 0, 12, 0, 0, 0, 0}
	case "named":
		child := append([]byte(nil), req[20:]...)
		req = make([]byte, 12+7*8)
		binary.BigEndian.PutUint32(req, codesign.MagicRequirements)
		binary.BigEndian.PutUint32(req[8:], 7)
		for i := 0; i < 7; i++ {
			binary.BigEndian.PutUint32(req[12+8*i:], uint32(i))
			binary.BigEndian.PutUint32(req[16+8*i:], uint32(len(req)))
			req = append(req, child...)
		}
		binary.BigEndian.PutUint32(req[4:], uint32(len(req)))
	default:
		if strings.HasPrefix(profile, "expr:") {
			req, err = codesign.CompileRequirements(strings.TrimPrefix(profile, "expr:"))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	err = codesign.Sign(context.Background(), path, codesign.SignOptions{Force: true, Identifier: "org.example.extract", Identity: identity, SigningTime: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC), Requirements: req, ForceLibraryEntitlements: true, Entitlements: []byte(`<plist><dict><key>test</key><true/></dict></plist>`)})
	if err != nil {
		t.Fatal(err)
	}
	if profile == "implicit-rsa" {
		// Signing now correctly inserts a certificate DR into an empty set.
		// Preserve extraction coverage for legacy signatures without one by
		// constructing a bound empty component and re-signing its CodeDirectory.
		withoutDesignatedRequirement(t, path, identity)
	}
	return path
}

func withoutDesignatedRequirement(t *testing.T, path string, identity *codesign.Identity) {
	t.Helper()
	report, err := codesign.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	executable := path
	if report.Bundle != nil {
		executable = report.Bundle.Executable
	}
	data := nativeRead(t, executable)
	for _, arch := range report.Architectures {
		base := int(arch.Offset + arch.SignatureOffset)
		var directory, requirements, cms int
		for i := 0; i < int(binary.BigEndian.Uint32(data[base+8:])); i++ {
			index := base + 12 + 8*i
			offset := base + int(binary.BigEndian.Uint32(data[index+4:]))
			switch binary.BigEndian.Uint32(data[index:]) {
			case codesign.SlotDirectory:
				directory = offset
			case codesign.SlotRequirements:
				requirements = offset
			case codesign.SlotCMS:
				cms = offset
			}
		}
		if directory == 0 || requirements == 0 || cms == 0 {
			t.Fatal("missing fixture components")
		}
		oldLength := int(binary.BigEndian.Uint32(data[requirements+4:]))
		clear(data[requirements+8 : requirements+oldLength])
		binary.BigEndian.PutUint32(data[requirements+4:], 12)
		sum := sha256.Sum256(data[requirements : requirements+12])
		hashOffset := directory + int(arch.Signature.Directories[0].HashOffset) - 64
		copy(data[hashOffset:hashOffset+32], sum[:])
		length := int(binary.BigEndian.Uint32(data[directory+4:]))
		signed, err := codesign.SignCMS(context.Background(), identity, [][]byte{data[directory : directory+length]}, time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		if len(signed)+8 != int(binary.BigEndian.Uint32(data[cms+4:])) {
			t.Fatal("fixture CMS allocation changed")
		}
		copy(data[cms+8:], signed)
	}
	if report.Format == "disk image" {
		// UDIF requires a tightly packed signature. Reuse the APFS footer model
		// to update the length, which is blinded in the bound trailer hash.
		base := int(report.Architectures[0].SignatureOffset)
		count := int(binary.BigEndian.Uint32(data[base+8:]))
		packed := bytes.Clone(data[base : base+12+count*8])
		for i := 0; i < count; i++ {
			index := 12 + i*8
			offset := base + int(binary.BigEndian.Uint32(data[base+index+4:]))
			length := int(binary.BigEndian.Uint32(data[offset+4:]))
			binary.BigEndian.PutUint32(packed[index+4:], uint32(len(packed)))
			packed = append(packed, data[offset:offset+length]...)
		}
		binary.BigEndian.PutUint32(packed[4:], uint32(len(packed)))
		var footer disk.DMGFooter
		size := binary.Size(footer)
		if err := binary.Read(bytes.NewReader(data[len(data)-size:]), binary.BigEndian, &footer); err != nil {
			t.Fatal(err)
		}
		footer.CodeSignatureLength = uint64(len(packed))
		var tail bytes.Buffer
		if err := binary.Write(&tail, binary.BigEndian, footer); err != nil {
			t.Fatal(err)
		}
		data = append(append(bytes.Clone(data[:base]), packed...), tail.Bytes()...)
	}
	if err := os.WriteFile(executable, data, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := codesign.Verify(context.Background(), path, codesign.VerifyOptions{TrustedCertificates: identity.Certificates}); err != nil {
		t.Fatal("legacy fixture binding", err)
	}
}

func TestRequirementExtraction(t *testing.T) {
	expressions := []string{`always`, `never`, `identifier "abc123"`, `identifier "true"`, `identifier "1abc"`, `identifier "é"`, `identifier "a\"b\\c"`, `identifier "a\nb"`, `anchor apple generic`, `certificate leaf[subject.CN] = Example`, `certificate root[subject.O] = "Test CA"`, `certificate 1[subject.OU] = ABC`, `certificate 1[field.1.2.840.113635.100.6.2.6] exists`, `certificate root = H"0000000000000000000000000000000000000000"`, `cdhash H"0123456789012345678901234567890123456789"`, `! (always or never)`, `always and never or always`}
	expressions = append(expressions, `identifier "`+strings.Repeat("a", 260)+`"`)
	for _, format := range []string{"arm64", "x86_64", "universal", "app", "framework", "dmg"} {
		profiles := []string{"implicit", "explicit", "named", "rsa", "chain", "implicit-rsa"}
		if format == "arm64" {
			for _, e := range expressions {
				profiles = append(profiles, "expr:"+e)
			}
		}
		for index, profile := range profiles {
			name := profile
			if strings.HasPrefix(profile, "expr:") {
				name = fmt.Sprintf("expression-%02d", index-6)
			}
			t.Run(format+"/"+name, func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				path := requirementInput(t, dir, format, profile)
				before := layoutArchive(t, dir)
				programs := []string{binaryPath}
				if runtime.GOOS == "darwin" {
					programs = append(programs, apple(t))
				}
				var goOut, goErr, nativeOut, nativeErr string
				for i, exe := range programs {
					out, stderr, code := run(t, exe, "-d", "-r-", path)
					if code != 0 || out == "" {
						t.Fatalf("%s exit=%d stdout=%q stderr=%q", exe, code, out, stderr)
					}
					if strings.HasPrefix(profile, "implicit") != strings.HasPrefix(out, "# designated => ") {
						t.Fatal("implicit comment", out)
					}
					if i == 0 {
						goOut, goErr = out, stderr
					} else {
						nativeOut, nativeErr = out, stderr
						nativeEqual(t, "stdout", []byte(out), []byte(goOut))
						nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
					}
					nativeEqual(t, "input preserved", layoutArchive(t, dir), before)
				}
				attest(t, map[string]any{"format": format, "profile": profile, "exit": 0, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash([]byte(goOut)), "input_sha256": hash(before), "native_compared": len(programs) == 2, "input_preserved": true})
			})
		}
	}
}

func TestRequirementOutputLifecycle(t *testing.T) {
	for _, mode := range []string{"create", "truncate", "hardlink", "symlink", "missing-parent", "directory", "empty-argument", "repeated", "multiple", "multiple-stdout", "continue-open", "entitlements", "entitlements-failure", "requirement-failure-first", "file-list", "file-list-failure", "certificate-failure", "certificate-success", "verbose", "json", "verify"} {
		t.Run(mode, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			profile := "explicit"
			if strings.HasPrefix(mode, "certificate-") {
				profile = "rsa"
			}
			path := requirementInput(t, dir, "arm64", profile)
			input := nativeRead(t, path)
			secondDir := filepath.Join(dir, "second")
			if e := os.Mkdir(secondDir, 0755); e != nil {
				t.Fatal(e)
			}
			second := requirementInput(t, secondDir, "arm64", "implicit")
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" && mode != "json" {
				programs = append(programs, apple(t))
			}
			var goOut, goErr, nativeOut, nativeErr string
			var after []byte
			status := 0
			for i, exe := range programs {
				if e := os.WriteFile(path, input, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.RemoveAll("out"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir("out", 0755); e != nil {
					t.Fatal(e)
				}
				dest := "out/result"
				args := []string{"-d"}
				want := 0
				var saved os.FileInfo
				if mode == "truncate" || mode == "hardlink" || mode == "symlink" {
					if e := os.WriteFile("out/original", bytes.Repeat([]byte("sentinel"), 100), 0600); e != nil {
						t.Fatal(e)
					}
					switch mode {
					case "hardlink":
						if e := os.Link("out/original", dest); e != nil {
							t.Fatal(e)
						}
					case "symlink":
						if e := os.Symlink("original", dest); e != nil {
							t.Fatal(e)
						}
					default:
						if e := os.Rename("out/original", dest); e != nil {
							t.Fatal(e)
						}
					}
					f, e := os.Open(dest)
					if e != nil {
						t.Fatal(e)
					}
					saved, e = f.Stat()
					_ = f.Close()
					if e != nil {
						t.Fatal(e)
					}
				}
				switch mode {
				case "missing-parent", "continue-open", "requirement-failure-first":
					dest = "out/missing/result"
					want = 1
				case "directory":
					dest = "out"
					want = 1
				case "empty-argument":
					dest = ""
					want = 1
				case "repeated":
					args = append(args, "--requirements=out/ignored")
				case "multiple-stdout":
					dest = "-"
				case "entitlements":
					args = append(args, "--entitlements=:-")
					dest = "-"
				case "entitlements-failure":
					args = append(args, "--entitlements=out/missing/ent")
					dest = "-"
					want = 1
				case "file-list":
					args = append(args, "--file-list=-")
				case "file-list-failure":
					args = append(args, "--file-list=out/missing/list")
					want = 1
				case "certificate-failure":
					args = append(args, "--extract-certificates=out/missing/cert")
					want = 1
				case "certificate-success":
					args = append(args, "--extract-certificates=out/cert")
				case "verbose":
					args[0] = "-dvvvv"
					dest = "-"
				case "json":
					args = append(args, "--json")
					dest = "-"
				case "verify":
					args = []string{"--verify"}
				}
				if mode == "requirement-failure-first" {
					args = append(args, "--entitlements=:-")
				}
				if mode == "continue-open" {
					args = append(args, "--continue")
				}
				args = append(args, "--requirements="+dest, path)
				if mode == "multiple" || mode == "multiple-stdout" || mode == "continue-open" {
					args = append(args, second)
				}
				out, stderr, code := run(t, exe, args...)
				if code != want {
					t.Fatalf("%s exit %d want %d stdout=%q stderr=%q", exe, code, want, out, stderr)
				}
				if saved != nil {
					now, e := os.Stat(dest)
					if e != nil || !os.SameFile(saved, now) || now.Mode().Perm() != saved.Mode().Perm() {
						t.Fatal("output inode/mode changed", e)
					}
					if bytes.Contains(nativeRead(t, dest), []byte("sentinel")) {
						t.Fatal("did not truncate")
					}
				}
				if mode == "verify" || mode == "certificate-failure" || mode == "repeated" {
					if _, e := os.Stat("out/ignored"); !os.IsNotExist(e) {
						t.Fatal("unexpected ignored destination", e)
					}
				}
				if mode == "verify" {
					if _, e := os.Stat(dest); !os.IsNotExist(e) {
						t.Fatal("unexpected non-display output", e)
					}
				}
				nativeEqual(t, "input unchanged", nativeRead(t, path), input)
				if i == 0 {
					goOut, goErr, after, status = out, stderr, layoutArchive(t, filepath.Join(dir, "out")), code
				} else {
					nativeOut, nativeErr = out, stderr
					nativeEqual(t, "stdout", []byte(out), []byte(goOut))
					nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
					nativeEqual(t, "output tree", layoutArchive(t, filepath.Join(dir, "out")), after)
				}
			}
			attest(t, map[string]any{"mode": mode, "exit": status, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash(after), "stdout_sha256": hash([]byte(goOut)), "input_sha256": hash(input), "native_compared": len(programs) == 2, "input_preserved": true})
		})
	}
}

func requirementMutate(t *testing.T, data []byte, state string) []byte {
	t.Helper()
	data = bytes.Clone(data)
	r, e := codesign.InspectBytes(data)
	if e != nil {
		t.Fatal(e)
	}
	a := r.Architectures[0]
	base := int(a.Offset + a.SignatureOffset)
	var cd int
	for i := 0; i < int(binary.BigEndian.Uint32(data[base+8:])); i++ {
		index := base + 12 + 8*i
		slot := binary.BigEndian.Uint32(data[index:])
		off := base + int(binary.BigEndian.Uint32(data[index+4:]))
		if slot == 0 {
			cd = off
		}
		if slot == 2 && (state == "missing" || state == "absent") {
			binary.BigEndian.PutUint32(data[index:], 99)
		}
		if slot == 0x10000 && state == "cms" {
			data[off+int(binary.BigEndian.Uint32(data[off+4:]))-1] ^= 1
		}
	}
	off := cd + int(a.Signature.Directories[0].HashOffset) - 64
	switch state {
	case "hash":
		data[off] ^= 1
	case "zero", "absent":
		clear(data[off : off+32])
	case "page":
		data[5000] ^= 1
	}
	return data
}

func TestRequirementSlotStates(t *testing.T) {
	for _, state := range []string{"hash", "missing", "zero", "absent", "page", "cms"} {
		t.Run(state, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			profile := "explicit"
			if state == "cms" {
				profile = "rsa"
			}
			path := requirementInput(t, dir, "arm64", profile)
			input := requirementMutate(t, nativeRead(t, path), state)
			if e := os.WriteFile(path, input, 0755); e != nil {
				t.Fatal(e)
			}
			programs := []string{binaryPath}
			if runtime.GOOS == "darwin" {
				programs = append(programs, apple(t))
			}
			want := 0
			if state == "hash" || state == "missing" {
				want = 1
			}
			var goErr, nativeErr string
			var after []byte
			for i, exe := range programs {
				if e := os.WriteFile("out", []byte("sentinel"), 0600); e != nil {
					t.Fatal(e)
				}
				out, stderr, code := run(t, exe, "-dvv", "--requirements=out", path)
				if code != want || out != "" {
					t.Fatal(exe, code, out, stderr)
				}
				got := nativeRead(t, "out")
				if want == 1 && len(got) != 0 {
					t.Fatal("destination not truncated before failure")
				}
				if i == 0 {
					goErr, after = stderr, got
				} else {
					nativeErr = stderr
					nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
					nativeEqual(t, "output", got, after)
				}
				nativeEqual(t, "input unchanged", nativeRead(t, path), input)
			}
			attest(t, map[string]any{"state": state, "exit": want, "stderr": goErr, "native_stderr": nativeErr, "output_sha256": hash(after), "input_sha256": hash(input), "input_preserved": true, "native_compared": len(programs) == 2})
		})
	}
}

func TestRequirementArchitectureSelection(t *testing.T) {
	for _, profile := range []string{"implicit", "explicit"} {
		for _, arch := range []string{"default", "arm64", "x86_64"} {
			t.Run(profile+"/"+arch, func(t *testing.T) {
				dir := extractionDirectory(t)
				path := requirementInput(t, dir, "universal", profile)
				input := nativeRead(t, path)
				// Give the first slice a different explicit expression while preserving its binding.
				if profile == "explicit" {
					r, _ := codesign.InspectBytes(input)
					a := r.Architectures[0]
					base := int(a.Offset + a.SignatureOffset)
					var cd, req int
					for i := 0; i < int(binary.BigEndian.Uint32(input[base+8:])); i++ {
						slot := binary.BigEndian.Uint32(input[base+12+8*i:])
						off := base + int(binary.BigEndian.Uint32(input[base+16+8*i:]))
						if slot == 0 {
							cd = off
						}
						if slot == 2 {
							req = off
						}
					}
					end := req + int(binary.BigEndian.Uint32(input[req+4:]))
					input[end-1] = 1
					h := sha256.Sum256(input[req:end])
					copy(input[cd+int(a.Signature.Directories[0].HashOffset)-64:], h[:])
					if e := os.WriteFile(path, input, 0755); e != nil {
						t.Fatal(e)
					}
				}
				args := []string{"-dvv", "-r-"}
				if arch != "default" {
					args = append(args, "-a", arch)
				}
				args = append(args, path)
				programs := []string{binaryPath}
				if runtime.GOOS == "darwin" {
					programs = append(programs, apple(t))
				}
				var goOut, goErr, nativeOut, nativeErr string
				for i, exe := range programs {
					out, stderr, code := run(t, exe, args...)
					if code != 0 {
						t.Fatal(exe, code, out, stderr)
					}
					if i == 0 {
						goOut, goErr = out, stderr
					} else {
						nativeOut, nativeErr = out, stderr
						nativeEqual(t, "stdout", []byte(out), []byte(goOut))
						nativeEqual(t, "stderr", []byte(stderr), []byte(goErr))
					}
					nativeEqual(t, "input unchanged", nativeRead(t, path), input)
				}
				attest(t, map[string]any{"profile": profile, "architecture": arch, "exit": 0, "stdout": goOut, "stderr": goErr, "native_stdout": nativeOut, "native_stderr": nativeErr, "output_sha256": hash([]byte(goOut)), "input_sha256": hash(input), "input_preserved": true, "native_compared": len(programs) == 2})
			})
		}
	}
}
