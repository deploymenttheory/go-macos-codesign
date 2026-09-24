package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func accessSeed(profile string) time.Time {
	if profile == "future" {
		return time.Now().Add(48 * time.Hour)
	}
	return time.Unix(978307200, 234567890)
}

func accessStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func accessArgs(operation string) []string {
	args := []string{"-fs", "-", "-i", "org.example.access", "--timestamp=none"}
	switch operation {
	case "remove", "remove-unsigned":
		return []string{"--remove-signature"}
	case "dryrun", "dryrun-unsigned":
		return append(args, "--dryrun")
	case "display":
		return []string{"-d"}
	case "display-verbose":
		return []string{"-dvvv"}
	case "verify":
		return []string{"--verify"}
	case "verify-deep":
		return []string{"--verify", "--deep"}
	}
	return args
}

func accessSignedInput(operation string) bool {
	switch operation {
	case "resign", "remove", "dryrun", "display", "verify":
		return true
	}
	return false
}

func TestStandaloneAccessTime(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		for _, alias := range []string{"direct", "relative", "chain", "parent"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"sign", "readonly", "resign", "remove", "remove-unsigned", "dryrun", "dryrun-unsigned", "display", "verify"} {
					t.Run(arch+"/"+alias+"/"+profile+"/"+operation, func(t *testing.T) {
						name := "unsigned-" + arch
						if accessSignedInput(operation) {
							name = "adhoc-" + arch
						}
						input := nativeRead(t, filepath.Join(root, "testdata/macho", name))
						compareStandaloneAccess(t, input, alias, profile, operation, false)
					})
				}
			}
		}
	}
}

func TestDMGAccessTime(t *testing.T) {
	for _, format := range []string{"raw", "zlib", "lzfse", "lzma", "apfs"} {
		input := dmgFixture(t, format)
		path := filepath.Join(t.TempDir(), "signed.dmg")
		if err := os.WriteFile(path, input, 0644); err != nil {
			t.Fatal(err)
		}
		mustRun(t, apple(t), "-s", "-", "-i", "org.example.access", "--timestamp=none", path)
		signed := nativeRead(t, path)
		for _, profile := range []string{"past", "future"} {
			for _, operation := range []string{"sign", "resign", "remove", "remove-unsigned", "dryrun", "dryrun-unsigned", "display", "verify"} {
				t.Run(format+"/"+profile+"/"+operation, func(t *testing.T) {
					data := input
					if accessSignedInput(operation) {
						data = signed
					}
					compareStandaloneAccess(t, data, "relative", profile, operation, true)
				})
			}
		}
	}
}

func compareStandaloneAccess(t *testing.T, input []byte, alias, profile, operation string, dmg bool) {
	t.Helper()
	execute := func(exe string) ([]byte, map[string]any) {
		f := newStandaloneAlias(t, alias, input)
		if alias == "direct" {
			f.input = f.target
		}
		if operation == "readonly" {
			if err := os.Chmod(f.target, 0551); err != nil {
				t.Fatal(err)
			}
		}
		seed := accessSeed(profile)
		for _, path := range []string{f.target, f.decoy} {
			if err := os.Chtimes(path, seed, time.Unix(946684800, 123456789)); err != nil {
				t.Fatal(err)
			}
		}
		before, decoy := accessStat(t, f.target), accessStat(t, f.decoy)
		args := append(accessArgs(operation), f.input)
		started := time.Now()
		out, stderr, status := run(t, exe, args...)
		finished := time.Now()
		removing := strings.HasPrefix(operation, "remove")
		wantStatus := 0
		if dmg && removing {
			wantStatus = 1
		}
		if status != wantStatus {
			t.Fatalf("%s %q: %d\n%s\n%s", exe, args, status, out, stderr)
		}
		// Snapshot metadata before reading output bytes or verifying signatures.
		after, other, decoyAfter := accessStat(t, f.target), accessStat(t, f.neighbour), accessStat(t, f.decoy)
		accessed := !dmg && operation != "display" && operation != "verify"
		rewritten := accessed && !strings.HasPrefix(operation, "dryrun")
		dmgDryRun := dmg && strings.HasPrefix(operation, "dryrun")
		inPlace := dmg && (operation == "sign" || operation == "resign" || dmgDryRun)
		at, neighbourAt := writerAccess(after), writerAccess(other)
		if accessed {
			for _, value := range []time.Time{at, neighbourAt} {
				if value.Before(started) || value.After(finished) {
					t.Fatalf("%s access %v outside [%v, %v]", exe, value, started, finished)
				}
			}
			if rewritten && !at.After(neighbourAt) {
				t.Fatalf("replacement access %v did not follow source access %v", at, neighbourAt)
			}
		} else if !at.Equal(seed) || !neighbourAt.Equal(seed) {
			t.Fatalf("read-only or DMG access changed: %v, %v, want %v", at, neighbourAt, seed)
		}
		if os.SameFile(before, after) == rewritten || !os.SameFile(before, other) {
			t.Fatal("wrong target or neighbour identity")
		}
		for _, info := range []os.FileInfo{after, other} {
			oldStat, newStat := before.Sys().(*syscall.Stat_t), info.Sys().(*syscall.Stat_t)
			if info.Mode() != before.Mode() || oldStat.Uid != newStat.Uid || oldStat.Gid != newStat.Gid {
				t.Fatal("mode or ownership changed")
			}
		}
		if dmgDryRun && (after.ModTime().Before(started) || after.ModTime().After(finished) || !writerBirth(after).Equal(writerBirth(before))) {
			t.Fatal("DMG dry run did not retain creation time and refresh modification time")
		}
		if !inPlace && (!other.ModTime().Equal(before.ModTime()) || !writerBirth(other).Equal(writerBirth(before))) {
			t.Fatalf("%s source write timestamps changed: mtime %v -> %v, birth %v -> %v", exe, before.ModTime(), other.ModTime(), writerBirth(before), writerBirth(other))
		}
		if !rewritten && !inPlace {
			oldStat, newStat := *before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)
			oldStat.Atimespec = newStat.Atimespec
			if oldStat != newStat {
				t.Fatal("non-writing operation changed unrelated metadata")
			}
		}
		if *decoy.Sys().(*syscall.Stat_t) != *decoyAfter.Sys().(*syscall.Stat_t) {
			t.Fatal("lexical decoy metadata changed")
		}
		f.checkLinks(t)
		result := nativeRead(t, f.target)
		neighbourBytes := input
		if inPlace {
			neighbourBytes = result
		}
		nativeEqual(t, "hard-link bytes", nativeRead(t, f.neighbour), neighbourBytes)
		nativeEqual(t, "lexical decoy bytes", nativeRead(t, f.decoy), input)
		if !rewritten && !inPlace {
			nativeEqual(t, "non-writing operation bytes", result, input)
		}
		switch operation {
		case "sign", "readonly", "resign", "dryrun", "display", "verify":
			if !dmgDryRun {
				mustRun(t, apple(t), "--verify", "--strict", f.target)
			}
		}
		if dmgDryRun {
			assertUnsignedDMG(t, apple(t), f.target)
		}
		return result, map[string]any{"argv": args, "stdout": out, "stderr": stderr, "exit": status, "started": started, "finished": finished, "before_access": seed, "after_access": at, "neighbour_access": neighbourAt, "accessed": accessed, "inode_replaced": rewritten, "in_place": inPlace, "aliases_preserved": true, "decoy_preserved": true, "output_sha256": hash(result)}
	}
	got, record := execute(binaryPath)
	want, native := execute(apple(t))
	nativeEqual(t, "access-time output", got, want)
	attest(t, map[string]any{"alias": alias, "profile": profile, "operation": operation, "dmg": dmg, "byte_equal": bytes.Equal(got, want), "go": record, "native": native, "native_compared": true, "filesystem_profile": "Darwin APFS standalone access time"})
}

func TestBundleReadOnlyAccessTime(t *testing.T) {
	for _, layout := range append([]string{"app"}, bundleLayouts...) {
		for _, arch := range []string{"arm64", "x86_64", "universal"} {
			for _, profile := range []string{"past", "future"} {
				for _, operation := range []string{"display", "display-verbose", "verify", "verify-deep"} {
					t.Run(layout+"/"+arch+"/"+profile+"/"+operation, func(t *testing.T) {
						execute := func(exe string) ([]byte, map[string]any) {
							app, _, _, _, executables := writerBundle(t, t.TempDir(), layout, arch)
							mustRun(t, apple(t), "-s", "-", "--deep", "--timestamp=none", app)
							before := layoutArchive(t, app)
							seed := accessSeed(profile)
							stats := map[string]syscall.Stat_t{}
							for _, name := range executables {
								path := filepath.Join(app, filepath.FromSlash(name))
								if err := os.Chtimes(path, seed, time.Unix(946684800, 123456789)); err != nil {
									t.Fatal(err)
								}
								stats[name] = *accessStat(t, path).Sys().(*syscall.Stat_t)
							}
							args := append(accessArgs(operation), app)
							out, stderr, status := run(t, exe, args...)
							if status != 0 {
								t.Fatalf("%s %q: %d\n%s\n%s", exe, args, status, out, stderr)
							}
							effects := map[string]any{}
							for name, old := range stats {
								info := accessStat(t, filepath.Join(app, filepath.FromSlash(name)))
								if *info.Sys().(*syscall.Stat_t) != old {
									t.Fatalf("read-only operation changed executable metadata: %s", name)
								}
								effects[name] = map[string]any{"before_access": seed, "after_access": writerAccess(info), "metadata_preserved": true}
							}
							after := layoutArchive(t, app)
							nativeEqual(t, "read-only tree", after, before)
							return after, map[string]any{"argv": args, "stdout": out, "stderr": stderr, "exit": status, "tree_sha256": hash(after), "executables": effects}
						}
						got, record := execute(binaryPath)
						want, native := execute(apple(t))
						nativeEqual(t, "read-only native tree", got, want)
						attest(t, map[string]any{"layout": layout, "architecture": arch, "profile": profile, "operation": operation, "go": record, "native": native, "native_compared": true})
					})
				}
			}
		}
	}
}
