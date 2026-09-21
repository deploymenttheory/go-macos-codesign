package acceptance

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Observed from native APFS enumeration and codesign failures, independently of
// the production hash API. n23 precedes CodeResources. Both collision pairs
// require name comparison; n100200/N22934 differ in case and length, with raw
// ASCII order opposite to the observed case-folded order.
var signatureCleanupOrder = []string{
	"n23", "CodeResources", "n100200", "N22934", "collision-17818", "collision-30606",
	"CodeDirectory", "CodeEntitlements", "CodeTopDirectory", "CodeSignature",
	"CodeEntitlementsDER", "aaa", "CodeLaunchConstraintResponsible", "000-first",
	"CodeLaunchConstraintParent", "CodeLibraryConstraint", "CodeRequirements",
	"CodeApplication", "CodeLaunchConstraintSelf", "zzz",
}

func TestBundleSignatureCleanupOrder(t *testing.T) {
	for _, layout := range append([]string{"app"}, bundleLayouts...) {
		badNames := signatureCleanupOrder
		operations := []string{"remove", "resign"}
		if layout != "app" {
			badNames = []string{"n23", "CodeResources", "n100200", "collision-30606"}
		} else {
			operations = append(operations, "remove-unsigned", "dryrun", "verify")
		}
		for _, bad := range badNames {
			for _, kind := range []string{"directory", "symlink"} {
				for _, operation := range operations {
					removing := strings.HasPrefix(operation, "remove")
					if bad == "CodeResources" && !removing {
						continue // signing-envelope directories have a separate commit-boundary matrix
					}
					t.Run(layout+"/"+bad+"/"+kind+"/"+operation, func(t *testing.T) {
						execute := func(exe string) ([]byte, map[string]any) {
							dir := t.TempDir()
							app, mainName, envelope, _, _ := writerBundle(t, dir, layout, "arm64")
							if operation != "remove-unsigned" {
								mustRun(t, exe, "-s", "-", "--deep", "--timestamp=none", app)
							}
							meta := filepath.Join(app, filepath.Dir(envelope))
							// Opposite creation orders must have the same partial-purge result.
							for i := range signatureCleanupOrder {
								if kind == "directory" {
									i = len(signatureCleanupOrder) - 1 - i
								}
								name := signatureCleanupOrder[i]
								if name != "CodeResources" || operation == "remove-unsigned" {
									bundleWrite(t, meta, name, []byte("stale "+name+"\n"))
								}
							}
							badPath := filepath.Join(meta, bad)
							if err := os.Remove(badPath); err != nil {
								t.Fatal(err)
							}
							outside := filepath.Join(dir, "outside")
							bundleWrite(t, dir, "outside", []byte("outside unchanged\n"))
							if kind == "directory" {
								bundleWrite(t, badPath, "keep", []byte("directory unchanged\n"))
							} else {
								rel, err := filepath.Rel(meta, outside)
								if err != nil {
									t.Fatal(err)
								}
								if err := os.Symlink(rel, badPath); err != nil {
									t.Fatal(err)
								}
							}
							main := filepath.Join(app, mainName)
							neighbour := filepath.Join(dir, "main-neighbour")
							if err := os.Link(main, neighbour); err != nil {
								t.Fatal(err)
							}
							original, err := os.Stat(main)
							if err != nil {
								t.Fatal(err)
							}
							other, err := os.Stat(neighbour)
							if err != nil || !os.SameFile(original, other) {
								t.Fatalf("initial executable link: %v", err)
							}
							originalData, before := nativeRead(t, main), layoutArchive(t, app)
							args, statusWant := []string{"-fs", "-", "--deep", "--timestamp=none"}, 1
							switch {
							case removing:
								args = []string{"--remove-signature"}
							case operation == "dryrun":
								args, statusWant = append(args, "--dryrun"), 0
							case operation == "verify":
								args = []string{"--verify", "--deep"}
							}
							out, stderr, status := run(t, exe, append(args, app)...)
							if status != statusWant {
								t.Fatalf("%s exit %d want %d: %s %s", exe, status, statusWant, out, stderr)
							}
							current, err := os.Stat(main)
							mutated := operation != "dryrun" && operation != "verify"
							if err != nil || os.SameFile(original, current) == mutated {
								t.Fatalf("executable replacement: %v", err)
							}
							other, err = os.Stat(neighbour)
							if err != nil || !os.SameFile(original, other) {
								t.Fatalf("neighbour identity: %v", err)
							}
							nativeEqual(t, "executable neighbour", nativeRead(t, neighbour), originalData)
							nativeEqual(t, "symlink target", nativeRead(t, outside), []byte("outside unchanged\n"))
							if kind == "directory" {
								nativeEqual(t, "rejected directory", nativeRead(t, filepath.Join(badPath, "keep")), []byte("directory unchanged\n"))
							}
							entries, err := os.ReadDir(meta)
							if err != nil {
								t.Fatal(err)
							}
							remaining, want := []string{}, []string{}
							for _, entry := range entries {
								remaining = append(remaining, entry.Name())
							}
							stop := slices.Index(signatureCleanupOrder, bad)
							for i, name := range signatureCleanupOrder {
								if !mutated || i >= stop || name == "CodeResources" && !removing {
									want = append(want, name)
								}
							}
							slices.Sort(want)
							if !slices.Equal(remaining, want) {
								t.Fatalf("partial cleanup: got %v want %v", remaining, want)
							}
							after := layoutArchive(t, app)
							if !mutated {
								nativeEqual(t, "non-mutating tree", after, before)
							}
							return after, map[string]any{"argv": append(args, app), "stdout": out, "stderr": stderr, "exit": status, "inode_replaced": mutated, "before_sha256": hash(before), "tree_sha256": hash(after), "remaining": remaining, "neighbour_preserved": true}
						}
						got, record := execute(binaryPath)
						evidence := map[string]any{"producer": runtime.GOOS, "layout": layout, "bad_name": bad, "profile": kind, "operation": operation, "go": record, "native_compared": runtime.GOOS == "darwin", "filesystem_profile": "case-insensitive APFS, ASCII names", "remaining_differences": []string{"other filesystem orders", "symlinked signing envelopes", "raw diagnostics and broader permissions"}}
						if runtime.GOOS == "darwin" {
							want, native := execute(apple(t))
							nativeEqual(t, "complete ordered cleanup failure tree", got, want)
							evidence["native"] = native
						}
						attest(t, evidence)
					})
				}
			}
		}
	}
}
