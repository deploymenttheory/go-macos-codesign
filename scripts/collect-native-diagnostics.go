//go:build ignore

// Collect bounded diagnostics from the ephemeral Mac CI runner after failure.
// This is test infrastructure, never imported by the production binary.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const limit = 4 << 20

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := limit - b.Len(); remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(n, remaining)])
	}
	return n, nil
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if runtime.GOOS != "darwin" {
		panic("native diagnostics require the Mac test host")
	}
	dest := filepath.Join("artifacts", "native-diagnostics")
	must(os.MkdirAll(dest, 0755))
	snapshot := time.Now().UTC()
	must(os.WriteFile(filepath.Join(dest, "collected-at.txt"), []byte(snapshot.Format(time.RFC3339Nano)+"\n"), 0644))
	for _, c := range []struct {
		name, exe string
		args      []string
	}{
		{"host", "/usr/bin/sw_vers", nil},
		{"memory", "/usr/bin/vm_stat", nil},
		{"swap", "/usr/sbin/sysctl", []string{"hw.memsize", "vm.swapusage"}},
		{"codesign-system-log", "/usr/bin/log", []string{"show", "--last", "25m", "--style", "compact", "--predicate", `(process == "codesign") OR ((process == "kernel" OR process == "amfid" OR process == "syspolicyd" OR process == "taskgated" OR process == "ReportCrash") AND (eventMessage CONTAINS[c] "codesign" OR eventMessage CONTAINS[c] "memorystatus" OR eventMessage CONTAINS[c] "jetsam"))`}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, c.exe, c.args...)
		var out boundedOutput
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		cancel()
		data := append([]byte(fmt.Sprintf("command=%q args=%q error=%v\n", c.exe, c.args, err)), out.Bytes()...)
		must(os.WriteFile(filepath.Join(dest, c.name+".txt"), data, 0644))
		fmt.Printf("saved %s (%d bytes; %v)\n", c.name, len(data), err)
	}
	exe, err := os.ReadFile("/usr/bin/codesign")
	must(err)
	must(os.WriteFile(filepath.Join(dest, "codesign-sha256.txt"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(exe))), 0644))
	home, err := os.UserHomeDir()
	must(err)
	for i, base := range []string{filepath.Join(home, "Library/Logs/DiagnosticReports"), "/Library/Logs/DiagnosticReports"} {
		entries, err := os.ReadDir(base)
		if err != nil {
			fmt.Printf("crash reports %s: %v\n", base, err)
			continue
		}
		copied := 0
		for _, entry := range entries {
			if copied == 32 {
				break
			}
			name := entry.Name()
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasPrefix(name, "codesign") || !(strings.HasSuffix(name, ".ips") || strings.HasSuffix(name, ".crash")) {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.ModTime().Before(snapshot.Add(-30*time.Minute)) {
				continue
			}
			f, err := os.Open(filepath.Join(base, name))
			if err != nil {
				fmt.Println("crash report open:", err)
				continue
			}
			data, err := io.ReadAll(io.LimitReader(f, limit))
			f.Close()
			if err != nil {
				fmt.Println("crash report read:", err)
				continue
			}
			must(os.WriteFile(filepath.Join(dest, fmt.Sprintf("report-%d-%s", i, name)), data, 0644))
			copied++
			fmt.Printf("saved %s (%d bytes)\n", name, len(data))
		}
	}
}
