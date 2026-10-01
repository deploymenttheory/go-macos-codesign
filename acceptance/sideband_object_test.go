package acceptance

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func sidebandObjectAttrs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names, err := hostdata.ListXattrNames(f, hostdata.MaxXattrListSize)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, name := range names {
		b, present, err := hostdata.ReadXattr(f, name, 8<<20)
		if err != nil || !present {
			t.Fatal(name, present, err)
		}
		values[name] = hex.EncodeToString(b)
	}
	return values
}

func setSidebandObject(t *testing.T, path string, metadata appledouble.File) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	attrs := append([]appledouble.Attr{}, metadata.Attrs...)
	if len(metadata.ResourceFork) > 0 {
		attrs = append(attrs, appledouble.Attr{Name: appledouble.ResourceForkName, Value: metadata.ResourceFork})
	}
	if metadata.FinderInfo != [32]byte{} {
		attrs = append(attrs, appledouble.Attr{Name: appledouble.FinderInfoName, Value: metadata.FinderInfo[:]})
	}
	for _, attr := range attrs {
		name := attr.Name
		if runtime.GOOS == "linux" && strings.HasPrefix(name, "com.apple.") {
			name = "user." + name
		}
		if err := hostdata.SetXattr(f, name, attr.Value); err != nil {
			t.Fatal(name, err)
		}
	}
}

func TestStandaloneSidebandVerification(t *testing.T) {
	for _, format := range []string{"arm64", "x86_64", "universal", "dmg"} {
		states := []string{"clean", "fork", "finder", "both", "ordinary", "corrupt-fork"}
		if format != "dmg" {
			states = append(states, "trailing-fork")
		}
		for _, state := range states {
			for _, transport := range []string{"native", "appledouble"} {
				t.Run(format+"/"+state+"/"+transport, func(t *testing.T) {
					dir := extractionDirectory(t)
					t.Chdir(dir)
					input := "testdata/macho/adhoc-" + format
					if format == "dmg" {
						input = "testdata/dmg/native-adhoc-raw.dmg"
					}
					data := nativeRead(t, filepath.Join(root, input))
					if state == "corrupt-fork" {
						offset := 4096
						switch format {
						case "universal":
							offset += int(binary.BigEndian.Uint32(data[16:]))
						case "dmg":
							offset = 0
						}
						data[offset] ^= 1
					}
					if state == "trailing-fork" {
						data = append(data, 0, 0, 0, 0)
					}
					metadata := appledouble.File{}
					if strings.Contains(state, "fork") || state == "both" {
						metadata.ResourceFork = []byte("resource fork")
					}
					if state == "finder" || state == "both" {
						copy(metadata.FinderInfo[:], "TEXTttxt")
					}
					if state == "ordinary" {
						metadata.Attrs = []appledouble.Attr{{Name: "user.codesign-control", Value: []byte("keep")}}
					}
					carrier, err := metadata.Encode()
					if err != nil {
						t.Fatal(err)
					}
					bundleWrite(t, dir, "metadata", carrier)
					bundleWrite(t, dir, "fixture", data)
					if transport == "native" {
						setSidebandObject(t, "fixture", metadata)
					}
					// An independent native object carries the same metadata on
					// macOS. Only its path prefix is normalized in comparisons.
					if runtime.GOOS == "darwin" {
						bundleWrite(t, dir, "native/fixture", data)
						setSidebandObject(t, "native/fixture", metadata)
					}
					before := layoutArchive(t, dir)
					attrs := sidebandObjectAttrs(t, "fixture")
					for _, policy := range []string{"default", "sideband", "all", "plain", "ignore-resources", "no-strict", "none"} {
						t.Run(policy, func(t *testing.T) {
							args := []string{"--verify", "--verbose=1"}
							switch policy {
							case "sideband", "all":
								args = append(args, "--strict="+policy)
							case "plain":
								args = append(args, "--strict")
							case "ignore-resources", "no-strict":
								args = append(args, "--strict=sideband", "--"+policy)
							case "none":
								args = append(args, "--strict=sideband", "--strict=none")
							}
							active := policy != "default" && policy != "no-strict" && policy != "none"
							goArgs := append([]string{}, args...)
							if transport == "appledouble" && active {
								goArgs = append(goArgs, "--appledouble", "metadata")
							}
							prohibited := format != "dmg" && (len(metadata.ResourceFork) != 0 || metadata.FinderInfo != [32]byte{}) && (transport == "appledouble" || runtime.GOOS != "linux")
							want := 0
							if active && prohibited || state == "corrupt-fork" || state == "trailing-fork" && policy != "none" && policy != "no-strict" {
								want = 1
							}
							out, stderr, status := run(t, binaryPath, append(goArgs, "fixture")...)
							if status != want {
								t.Fatal(status, want, out, stderr)
							}
							nout, nerr := "", ""
							if runtime.GOOS == "darwin" {
								nattrs := sidebandObjectAttrs(t, "native/fixture")
								var nstatus int
								nout, nerr, nstatus = run(t, apple(t), append(args, "native/fixture")...)
								normalize := func(s string) string {
									return strings.ReplaceAll(s, "native/fixture", "fixture")
								}
								if nstatus != status || normalize(nout) != out || normalize(nerr) != stderr {
									t.Fatal("native sideband object comparison", status, nstatus, out, nout, stderr, nerr)
								}
								if !reflect.DeepEqual(nattrs, sidebandObjectAttrs(t, "native/fixture")) {
									t.Fatal("native command changed metadata")
								}
							}
							nativeEqual(t, "sideband input bytes/modes/links", layoutArchive(t, dir), before)
							if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, "fixture")) || !bytes.Equal(carrier, nativeRead(t, "metadata")) {
								t.Fatal("metadata or carrier changed")
							}
							attest(t, map[string]any{"format": format, "state": state, "transport": transport, "policy": policy, "exit": status, "stdout": out, "stderr": stderr,
								"native_stdout": nout, "native_stderr": nerr, "native_compared": runtime.GOOS == "darwin", "input_preserved": true,
								"code_sha256": hash(data), "carrier_sha256": hash(carrier), "attrs": attrs, "fixture_root": dir})
						})
					}
				})
			}
		}
	}
}

func TestStandaloneSidebandAliases(t *testing.T) {
	for _, link := range []string{"symbolic", "hard"} {
		t.Run(link, func(t *testing.T) {
			dir := extractionDirectory(t)
			t.Chdir(dir)
			copyFixture(t, "adhoc-arm64", "fixture")
			metadata := appledouble.File{ResourceFork: []byte("fork")}
			encoded, err := metadata.Encode()
			if err != nil {
				t.Fatal(err)
			}
			bundleWrite(t, dir, "metadata", encoded)
			if link == "symbolic" {
				err = os.Symlink("fixture", "alias")
			} else {
				err = os.Link("fixture", "alias")
			}
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--verify", "--verbose=1", "--strict=sideband"}
			before, attrs := layoutArchive(t, dir), sidebandObjectAttrs(t, "fixture")
			path := filepath.Join(dir, "fixture")
			if link == "hard" {
				path = filepath.Join(dir, "alias")
			}
			out, stderr, status := run(t, binaryPath, append(append([]string{}, args...), "--appledouble", "metadata", "alias")...)
			want := fmt.Sprintf("file with invalid attached data: Disallowed xattr com.apple.ResourceFork found on %s\n", path)
			if status != 1 || out != want {
				t.Fatal(status, out, want, stderr)
			}
			nativeEqual(t, "carrier alias preservation", layoutArchive(t, dir), before)
			if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, "fixture")) {
				t.Fatal("carrier alias metadata changed")
			}
			if runtime.GOOS == "darwin" {
				// Stage native metadata only after the carrier-only check. Each
				// command has its own preservation boundary around that setup.
				setSidebandObject(t, "fixture", metadata)
				before, attrs := layoutArchive(t, dir), sidebandObjectAttrs(t, "fixture")
				nout, nerr, nstatus := run(t, apple(t), append(args, "alias")...)
				if nstatus != status || out != nout || stderr != nerr {
					t.Fatal(nstatus, nout, nerr, status, out, stderr)
				}
				nativeEqual(t, "native alias preservation", layoutArchive(t, dir), before)
				if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, "fixture")) {
					t.Fatal("native alias metadata changed")
				}
			}
			attest(t, map[string]any{"link": link, "exit": status, "stdout": out, "stderr": stderr, "input_preserved": true, "native_compared": runtime.GOOS == "darwin", "carrier_sha256": hash(encoded), "fixture_root": dir})
		})
	}
}

func TestStandaloneSidebandArchitectureSelection(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		for _, selected := range []string{"", "arm64", "x86_64"} {
			t.Run(fmt.Sprintf("corrupt-%t/%s", corrupt, selected), func(t *testing.T) {
				dir := extractionDirectory(t)
				t.Chdir(dir)
				data := nativeRead(t, filepath.Join(root, "testdata/macho/adhoc-universal"))
				if corrupt {
					// This fixture's physical first slice is x86_64. Native
					// all-architecture traversal starts with the arm64 slice.
					data[int(binary.BigEndian.Uint32(data[16:]))+4096] ^= 1
				}
				bundleWrite(t, dir, "fixture", data)
				metadata := appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}}
				encoded, err := metadata.Encode()
				if err != nil {
					t.Fatal(err)
				}
				bundleWrite(t, dir, "metadata", encoded)
				args := []string{"--verify", "--verbose=1", "--strict=all"}
				if selected != "" {
					args = append(args, "--architecture", selected)
				}
				before, attrs := layoutArchive(t, dir), sidebandObjectAttrs(t, "fixture")
				out, stderr, status := run(t, binaryPath, append(append([]string{}, args...), "--appledouble", "metadata", "fixture")...)
				if status != 1 {
					t.Fatal(status, out, stderr)
				}
				codeError := corrupt && selected != "arm64"
				if strings.Contains(stderr, "code or signature have been modified") != codeError || strings.Contains(out, appledouble.ResourceForkName) == codeError {
					t.Fatal("architecture/metadata order", status, out, stderr)
				}
				nativeEqual(t, "selected architecture preservation", layoutArchive(t, dir), before)
				if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, "fixture")) {
					t.Fatal("selected architecture metadata changed")
				}
				nout, nerr := "", ""
				if runtime.GOOS == "darwin" {
					setSidebandObject(t, "fixture", metadata)
					attrs = sidebandObjectAttrs(t, "fixture")
					var nstatus int
					nout, nerr, nstatus = run(t, apple(t), append(args, "fixture")...)
					if nstatus != status || nout != out || nerr != stderr {
						t.Fatal(nstatus, nout, nerr, status, out, stderr)
					}
					nativeEqual(t, "native selected architecture preservation", layoutArchive(t, dir), before)
					if !reflect.DeepEqual(attrs, sidebandObjectAttrs(t, "fixture")) {
						t.Fatal("native selected architecture metadata changed")
					}
				}
				attest(t, map[string]any{"selection": selected, "corrupt": corrupt, "exit": status, "stdout": out, "stderr": stderr, "native_stdout": nout, "native_stderr": nerr,
					"native_compared": runtime.GOOS == "darwin", "input_preserved": true, "code_sha256": hash(data), "carrier_sha256": hash(encoded), "fixture_root": dir})
			})
		}
	}
}
