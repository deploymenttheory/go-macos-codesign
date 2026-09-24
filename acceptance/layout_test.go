package acceptance

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"
)

var bundleLayouts = []string{"bundle", "plugin", "xpc", "appex", "framework", "versioned"}

func layoutPaths(kind string) (ext, base, info, executable string) {
	ext, base, info, executable = kind, "Contents/", "Info.plist", "MacOS/Fixture"
	if kind == "framework" || kind == "versioned" {
		ext, base, info, executable = "framework", "", "Resources/Info.plist", "Fixture"
		if kind == "versioned" {
			base = "Versions/A/"
		}
	}
	return
}

func layoutLink(t *testing.T, dir, name, target string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatalf("symlink %s -> %s: %v", name, target, err)
	}
}

func layoutFixture(t *testing.T, dir, kind, arch, metadata string) string {
	t.Helper()
	ext, base, info, executable := layoutPaths(kind)
	bundle := filepath.Join(dir, "Fixture."+ext)
	typ, input := "BNDL", "testdata/macho/unsigned-"+arch
	if kind == "bundle" || kind == "plugin" {
		input = "testdata/layouts/unsigned-" + arch + ".bundle"
	}
	if kind == "xpc" || kind == "appex" {
		typ = "XPC!"
	}
	if kind == "framework" || kind == "versioned" {
		typ, input = "FMWK", "testdata/nested/unsigned-"+arch+".dylib"
	}
	data := []byte(fmt.Sprintf(`<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Fixture</string><key>CFBundleIdentifier</key><string>org.example.layout</string><key>CFBundlePackageType</key><string>%s</string></dict></plist>`, typ))
	if metadata == "binary" {
		var values map[string]any
		if _, err := plist.Unmarshal(data, &values); err != nil {
			t.Fatal(err)
		}
		var err error
		data, err = plist.Marshal(values, plist.BinaryFormat)
		if err != nil {
			t.Fatal(err)
		}
	}
	bundleWrite(t, bundle, base+info, data)
	bundleWrite(t, bundle, base+executable, nativeRead(t, filepath.Join(root, input)))
	if err := os.Chmod(filepath.Join(bundle, filepath.FromSlash(base+executable)), 0755); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"Resources/message.txt": "hello\n", "Resources/Base.lproj/hello": "base\n", "Resources/fr.lproj/hello": "local\n", "Resources/fr.lproj/locversion.plist": "ignored\n", "Resources/.DS_Store": "public test data\n", "version.plist": "version\n"} {
		bundleWrite(t, bundle, base+name, []byte(text))
	}
	if typ == "FMWK" {
		bundleWrite(t, bundle, base+"Headers/Fixture.h", []byte("int fixture(void);\n"))
		bundleWrite(t, bundle, base+"Modules/module.modulemap", []byte("framework module Fixture { umbrella header \"Fixture.h\" export * }\n"))
		// The root-level rule classifies this additional executable as nested code.
		bundleWrite(t, bundle, base+"helper", nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-"+arch)))
	}
	layoutLink(t, bundle, base+"Resources/alias", "message.txt")
	layoutLink(t, bundle, base+"Resources/fr.lproj/alias", "../message.txt")
	if kind == "versioned" {
		layoutLink(t, bundle, "Versions/Current", "A")
		for _, name := range []string{"Fixture", "Resources", "Headers", "Modules"} {
			layoutLink(t, bundle, name, "Versions/Current/"+name)
		}
	}
	return bundle
}

// ZIP artifact transport dereferences links. A tar member preserves each target
// spelling, including Windows-created links normalized back to POSIX separators.
func layoutArchive(t *testing.T, bundle string, exclude ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	err := filepath.WalkDir(bundle, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == bundle {
			return nil
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(bundle, p)
		if err != nil {
			return err
		}
		for _, name := range exclude {
			if filepath.ToSlash(rel) == name {
				return nil
			}
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0644, Typeflag: tar.TypeReg, Size: st.Size()}
		switch {
		case d.IsDir():
			h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0755, 0
		case d.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, filepath.ToSlash(target), 0
		default:
			// Keep executable bits portable; signature verification is independent
			// of these bits, but the extracted Mach-O files should be runnable.
			data := nativeRead(t, p)
			if len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) || bytes.Equal(data[:4], []byte{0xca, 0xfe, 0xba, 0xbe})) {
				h.Mode = 0755
			}
		}
		if err := w.WriteHeader(h); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			_, err = w.Write(nativeRead(t, p))
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func extractLayout(t *testing.T, data []byte, dir string) {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(data))
	links := map[string]string{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !fs.ValidPath(h.Name) || h.Size > 8<<20 || strings.Contains(h.Name, "\\") {
			t.Fatal("invalid test archive member", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(h.Name)), 0755); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg:
			b, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			bundleWrite(t, dir, h.Name, b)
			if err := os.Chmod(filepath.Join(dir, filepath.FromSlash(h.Name)), fs.FileMode(h.Mode)&0777); err != nil {
				t.Fatal(err)
			}
		case tar.TypeSymlink:
			if strings.HasPrefix(h.Linkname, "/") || strings.Contains(h.Linkname, "\\") || !fs.ValidPath(path.Clean(path.Join(path.Dir(h.Name), h.Linkname))) {
				t.Fatal("invalid test archive link")
			}
			links[h.Name] = h.Linkname
		default:
			t.Fatal("unsupported test archive member")
		}
	}
	// Create directory aliases after physical targets exist, then remaining links.
	for name, target := range links {
		if name == "Versions/Current" || strings.HasSuffix(name, "/Versions/Current") {
			layoutLink(t, dir, name, target)
			delete(links, name)
		}
	}
	for name, target := range links {
		layoutLink(t, dir, name, target)
	}
}

func TestAppleBundleLayouts(t *testing.T) {
	reference := apple(t)
	for _, kind := range bundleLayouts {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, metadata := range []string{"xml", "binary"} {
				t.Run(kind+"/"+arch+"/"+metadata, func(t *testing.T) {
					native := layoutFixture(t, t.TempDir(), kind, arch, metadata)
					portable := layoutFixture(t, t.TempDir(), kind, arch, metadata)
					args := []string{"-s", "-", "--deep", "--timestamp=none"}
					mustRun(t, reference, append(args, native)...)
					mustRun(t, binaryPath, append(args, portable)...)
					nativeEqual(t, "complete layout", layoutArchive(t, portable), layoutArchive(t, native))
					for v := 0; v <= 4; v++ {
						option := "-d" + strings.Repeat("v", v)
						_, want, wc := run(t, reference, option, native)
						_, got, gc := run(t, binaryPath, option, portable)
						resolved, err := filepath.EvalSymlinks(native)
						if err != nil {
							t.Fatal(err)
						}
						resolvedGo, err := filepath.EvalSymlinks(portable)
						if err != nil {
							t.Fatal(err)
						}
						if wc != gc || strings.ReplaceAll(got, resolvedGo, "<bundle>") != strings.ReplaceAll(want, resolved, "<bundle>") {
							t.Fatalf("display %s\nGo: %s\nApple: %s", option, got, want)
						}
					}
					mustRun(t, reference, "--verify", "--strict", "--deep", portable)
					mustRun(t, binaryPath, "--verify", "--deep", native)
					before := layoutArchive(t, portable)
					mustRun(t, binaryPath, "-fs", "-", "--deep", "--dryrun", portable)
					if !bytes.Equal(before, layoutArchive(t, portable)) {
						t.Fatal("dryrun changed layout")
					}
					attest(t, map[string]any{"layout": kind, "architecture": arch, "metadata": metadata, "complete_tree_bytes_equal": true, "display_levels": 5, "native_strict_deep_verified": true, "dryrun_preserved": true})
				})
			}
		}
	}
}

func TestPortableBundleLayouts(t *testing.T) {
	for _, kind := range bundleLayouts {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, identity := range []string{"adhoc", "rsa", "p256"} {
				t.Run(kind+"/"+arch+"/"+identity, func(t *testing.T) {
					bundle := layoutFixture(t, t.TempDir(), kind, arch, "binary")
					id := "-"
					verify := []string{"--verify", "--deep"}
					if identity != "adhoc" {
						id = filepath.Join(root, "testdata/identities/"+identity+"-identity.pem")
						verify = append(verify, "--trust", filepath.Join(root, "testdata/identities/"+identity+"-cert.pem"))
					}
					mustRun(t, binaryPath, "-s", id, "--deep", "--timestamp=none", bundle)
					mustRun(t, binaryPath, append(verify, bundle)...)
					if runtime.GOOS == "darwin" {
						mustRun(t, apple(t), "--verify", "--strict", "--deep", bundle)
					}
					archive := layoutArchive(t, bundle)
					if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
						bundleWrite(t, export, "signed-layout-"+kind+"-"+identity+"-"+arch+".tar", archive)
					}
					copy := filepath.Join(t.TempDir(), filepath.Base(bundle))
					extractLayout(t, archive, copy)
					mustRun(t, binaryPath, append(verify, copy)...)
					attest(t, map[string]any{"layout": kind, "architecture": arch, "identity": identity, "archive_sha256": hash(archive), "native_strict_deep_verified": runtime.GOOS == "darwin"})
				})
			}
		}
	}
}

func TestLayoutRemoval(t *testing.T) {
	for _, kind := range bundleLayouts {
		t.Run(kind, func(t *testing.T) {
			bundle := layoutFixture(t, t.TempDir(), kind, "arm64", "xml")
			mustRun(t, binaryPath, "-s", "-", "--deep", bundle)
			_, base, _, executable := layoutPaths(kind)
			before := nativeRead(t, filepath.Join(bundle, base+"Resources/message.txt"))
			mustRun(t, binaryPath, "--remove-signature", bundle)
			entries, err := os.ReadDir(filepath.Join(bundle, base+"_CodeSignature"))
			if err != nil || len(entries) != 0 {
				t.Fatal("signature directory must remain empty", entries, err)
			}
			if !reflect.DeepEqual(before, nativeRead(t, filepath.Join(bundle, base+"Resources/message.txt"))) {
				t.Fatal("changed resource")
			}
			_, _, code := run(t, binaryPath, "--verify", filepath.Join(bundle, base+executable))
			if code == 0 {
				t.Fatal("signature retained")
			}
		})
	}
}

func TestAppleLayoutRemoval(t *testing.T) {
	reference := apple(t)
	for _, kind := range bundleLayouts {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(kind+"/"+arch, func(t *testing.T) {
				native, portable := layoutFixture(t, t.TempDir(), kind, arch, "xml"), layoutFixture(t, t.TempDir(), kind, arch, "xml")
				mustRun(t, reference, "-s", "-", "--deep", native)
				mustRun(t, binaryPath, "-s", "-", "--deep", portable)
				mustRun(t, reference, "--remove-signature", native)
				mustRun(t, binaryPath, "--remove-signature", portable)
				_, base, _, executable := layoutPaths(kind)
				main := base + executable
				goMain, nativeMain := nativeRead(t, filepath.Join(portable, main)), nativeRead(t, filepath.Join(native, main))
				assertRemoved(t, goMain)
				assertRemoved(t, nativeMain)
				nativeEqual(t, "removed entire bundle", layoutArchive(t, portable), layoutArchive(t, native))
				attest(t, map[string]any{"layout": kind, "architecture": arch, "native_removal_complete_tree_bytes_equal": true})
			})
		}
	}
}

func TestRecordAppleLayoutFixtures(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_LAYOUTS") != "1" {
		t.Skip("opt-in native layout recording")
	}
	reference := apple(t)
	dir := filepath.Join(root, "testdata/layouts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "README.md" {
			t.Fatal("refusing to overwrite", entry.Name())
		}
	}
	hashes := map[string]string{}
	compiler, stderr, code := run(t, "xcrun", "--find", "clang")
	if code != 0 {
		t.Fatal(stderr)
	}
	compiler = strings.TrimSpace(compiler)
	sdk, stderr, code := run(t, "xcrun", "--show-sdk-path")
	if code != 0 {
		t.Fatal(stderr)
	}
	sdk = strings.TrimSpace(sdk)
	version, _, _ := run(t, compiler, "--version")
	source := filepath.Join(root, "testdata/nested/library.c")
	for _, arch := range []string{"arm64", "x86_64"} {
		mustRun(t, compiler, "-isysroot", sdk, "-arch", arch, "-bundle", "-Wl,-no_adhoc_codesign", "-Wl,-headerpad,0x1000", "-o", filepath.Join(dir, "unsigned-"+arch+".bundle"), source)
	}
	mustRun(t, "xcrun", "lipo", "-create", filepath.Join(dir, "unsigned-arm64.bundle"), filepath.Join(dir, "unsigned-x86_64.bundle"), "-output", filepath.Join(dir, "unsigned-universal.bundle"))
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		name := "unsigned-" + arch + ".bundle"
		hashes[name] = hash(nativeRead(t, filepath.Join(dir, name)))
	}
	for _, kind := range bundleLayouts {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			bundle := layoutFixture(t, t.TempDir(), kind, arch, "binary")
			mustRun(t, reference, "-s", "-", "--deep", "--timestamp=none", bundle)
			mustRun(t, reference, "--verify", "--strict", "--deep", bundle)
			data := layoutArchive(t, bundle)
			name := kind + "-" + arch + ".tar"
			bundleWrite(t, dir, name, data)
			hashes[name] = hash(data)
		}
	}
	host, _, _ := run(t, "/usr/bin/sw_vers")
	record := map[string]any{"schema": 1, "files": hashes, "host": strings.TrimSpace(host), "codesign_sha256": hash(nativeRead(t, reference)), "source": "acceptance/layout_test.go: TestRecordAppleLayoutFixtures", "metadata": "binary Info.plist via pinned howett.net/plist", "sign_arguments": []string{"-s", "-", "--deep", "--timestamp=none", "<bundle>"}, "verify_arguments": []string{"--verify", "--strict", "--deep", "<bundle>"}, "native_strict_deep_verified": true, "archive": "deterministic POSIX tar preserving symlink targets"}
	record["compiler"], record["compiler_sha256"], record["sdk"] = strings.TrimSpace(version), hash(nativeRead(t, compiler)), sdk
	record["compile_source"], record["compile_source_sha256"] = "testdata/nested/library.c", hash(nativeRead(t, source))
	record["compile_arguments"] = []string{"-isysroot", "<sdk>", "-arch", "<architecture>", "-bundle", "-Wl,-no_adhoc_codesign", "-Wl,-headerpad,0x1000", "-o", "<output>", "testdata/nested/library.c"}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bundleWrite(t, dir, "manifest.json", append(data, '\n'))
}

func TestNativeLayoutFixtures(t *testing.T) {
	for _, kind := range bundleLayouts {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			t.Run(kind+"/"+arch, func(t *testing.T) {
				ext, _, _, _ := layoutPaths(kind)
				bundle := filepath.Join(t.TempDir(), "Fixture."+ext)
				data := nativeRead(t, filepath.Join(root, "testdata/layouts", kind+"-"+arch+".tar"))
				extractLayout(t, data, bundle)
				mustRun(t, binaryPath, "--verify", "--deep", bundle)
				portable := layoutFixture(t, t.TempDir(), kind, arch, "binary")
				mustRun(t, binaryPath, "-s", "-", "--deep", portable)
				nativeEqual(t, "native archive", layoutArchive(t, portable), data)
				attest(t, map[string]any{"layout": kind, "architecture": arch, "native_fixture_bytes_equal": true})
			})
		}
	}
}
