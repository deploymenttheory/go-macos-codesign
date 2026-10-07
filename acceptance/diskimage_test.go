package acceptance

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

// Match the SDK harness's ordinary-device cleanup policy. A busy detach can
// unmount volumes before failing to eject the image, so a mount path is not a
// stable retry target. This is test infrastructure, not a production backend.
func attachedTestDevice(data []byte) (string, error) {
	var attached struct {
		Entities []struct {
			Device string `plist:"dev-entry"`
		} `plist:"system-entities"`
	}
	if _, err := plist.Unmarshal(data, &attached); err != nil {
		return "", err
	}
	for _, entity := range attached.Entities {
		if number, ok := strings.CutPrefix(entity.Device, "/dev/disk"); ok && number != "" {
			if _, err := strconv.ParseUint(number, 10, 32); err == nil && !strings.HasPrefix(number, "+") {
				return entity.Device, nil
			}
		}
	}
	return "", fmt.Errorf("attachment has no backing device")
}

func detachTestImage(ctx context.Context, operation func() (int, error), pause func(context.Context, time.Duration) error) error {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		code, err := operation()
		if code == 0 && err == nil {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("detach exit %d without command error", code)
		}
		if code != 16 || attempt == 10 {
			return fmt.Errorf("detach failed after %d attempts: %w", attempt, err)
		}
		if canceled := pause(ctx, time.Second); canceled != nil {
			return errors.Join(err, canceled)
		}
	}
}

func waitForImageDetach(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func TestMountedFilesystemDetachPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		codes     []int
		wantCalls int
		valid     bool
	}{
		{"success", []int{0}, 1, true},
		{"busy-then-success", []int{16, 16, 0}, 3, true},
		{"busy-exhausted", []int{16}, 10, false},
		{"other-error", []int{1}, 1, false},
		{"busy-then-other-error", []int{16, 1}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, pauses := 0, 0
			failure := errors.New("native failure")
			err := detachTestImage(t.Context(), func() (int, error) {
				code := tc.codes[min(calls, len(tc.codes)-1)]
				calls++
				if code == 0 {
					return code, nil
				}
				return code, failure
			}, func(ctx context.Context, delay time.Duration) error {
				if delay != time.Second {
					t.Fatal("wrong retry delay", delay)
				}
				pauses++
				return ctx.Err()
			})
			if calls != tc.wantCalls || pauses != calls-1 || (err == nil) != tc.valid || !tc.valid && !errors.Is(err, failure) {
				t.Fatalf("calls=%d pauses=%d error=%v", calls, pauses, err)
			}
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		failure := errors.New("busy")
		err := detachTestImage(ctx, func() (int, error) { cancel(); return 16, failure }, waitForImageDetach)
		if !errors.Is(err, failure) || !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		err = detachTestImage(ctx, func() (int, error) { t.Fatal("command after cancellation"); return 0, nil }, waitForImageDetach)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := waitForImageDetach(t.Context(), 0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid-command-result", func(t *testing.T) {
		if err := detachTestImage(t.Context(), func() (int, error) { return 1, nil }, waitForImageDetach); err == nil {
			t.Fatal("accepted missing command error")
		}
	})
	t.Run("attachment", func(t *testing.T) {
		for _, devices := range [][]string{{"/dev/disk5", "/dev/disk6", "/dev/disk6s1"}, {"/dev/disk5s1"}, {"/dev/disk"}, {"/dev/disk+5"}, {}} {
			entities := make([]map[string]string, len(devices))
			for i, device := range devices {
				entities[i] = map[string]string{"dev-entry": device}
			}
			data, err := plist.Marshal(map[string]any{"system-entities": entities}, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			device, err := attachedTestDevice(data)
			if len(devices) == 3 {
				if err != nil || device != "/dev/disk5" {
					t.Fatal(device, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid attachment", devices)
			}
		}
		if _, err := attachedTestDevice([]byte("invalid")); err == nil {
			t.Fatal("accepted malformed attachment")
		}
	})
}
