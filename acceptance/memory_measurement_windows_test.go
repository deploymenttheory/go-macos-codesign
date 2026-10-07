package acceptance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// x/sys has no GetProcessMemoryInfo wrapper. The test harness asks .NET for the
// live Go worker's peak working set; it never reports PowerShell's own memory.
// No subprocess or custom native binding is introduced into production.
func processPeakMemory(ctx context.Context) (uint64, error) {
	script := fmt.Sprintf("$metadataProcess = [System.Diagnostics.Process]::GetProcessById(%d); $metadataProcess.Refresh(); [Console]::Write($metadataProcess.PeakWorkingSet64)", os.Getpid())
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("observe Go worker peak working set: %w: %s", err, output)
	}
	return strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
}
