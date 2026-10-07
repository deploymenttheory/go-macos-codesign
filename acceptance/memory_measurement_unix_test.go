//go:build darwin || linux

package acceptance

import (
	"context"
	"runtime"

	"golang.org/x/sys/unix"
)

func processPeakMemory(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	bytes := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		bytes *= 1024 // Darwin reports bytes; Linux reports KiB.
	}
	return bytes, nil
}
