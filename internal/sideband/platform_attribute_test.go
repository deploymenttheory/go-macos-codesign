package sideband

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"
)

// Test the native presence-query contract on every producer. Only Darwin's
// query EPERM becomes absence; inventory failures and EACCES remain errors.
func TestPlatformAttributePermissionPolicy(t *testing.T) {
	const attribute = "com.apple.root.installed"
	denied := fmt.Errorf("query: %w", syscall.EACCES)
	notPermitted := fmt.Errorf("query: %w", syscall.EPERM)
	for _, tc := range []struct {
		name, platform          string
		inventory               []string
		listErr, queryErr, want error
		size                    int
		present                 bool
		calls                   []string
	}{
		{name: "darwin/absent", platform: "darwin", calls: []string{attribute}},
		{name: "darwin/empty", platform: "darwin", present: true, calls: []string{attribute}},
		{name: "darwin/present", platform: "darwin", present: true, size: 17, calls: []string{attribute}},
		{name: "darwin/eperm", platform: "darwin", queryErr: notPermitted, calls: []string{attribute}},
		{name: "darwin/eacces", platform: "darwin", queryErr: denied, want: denied, calls: []string{attribute}},
		{name: "darwin/io", platform: "darwin", queryErr: syscall.EIO, want: syscall.EIO, calls: []string{attribute}},
		{name: "appledouble/eperm", platform: "appledouble", queryErr: notPermitted, calls: []string{attribute}},
		{name: "appledouble/eacces", platform: "appledouble", queryErr: denied, want: denied, calls: []string{attribute}},
		{name: "appledouble/io", platform: "appledouble", queryErr: syscall.EIO, want: syscall.EIO, calls: []string{attribute}},
		{name: "windows/absent", platform: "windows", calls: []string{attribute}},
		{name: "windows/present", platform: "windows", present: true, size: 17, calls: []string{attribute}},
		{name: "windows/eperm", platform: "windows", queryErr: notPermitted, want: notPermitted, calls: []string{attribute}},
		{name: "windows/eacces", platform: "windows", queryErr: denied, want: denied, calls: []string{attribute}},
		{name: "linux/absent", platform: "linux", calls: []string{"inventory"}},
		{name: "linux/no-namespace-remapping", platform: "linux", inventory: []string{"user." + attribute}, calls: []string{"inventory"}},
		{name: "linux/inventory-denied", platform: "linux", listErr: denied, want: denied, calls: []string{"inventory"}},
		{name: "linux/inventory-eperm", platform: "linux", listErr: notPermitted, want: notPermitted, calls: []string{"inventory"}},
		// A provider reporting the exact attribute still requires a real query.
		{name: "linux/present", platform: "linux", inventory: []string{attribute}, present: true, size: 17, calls: []string{"inventory", attribute}},
		{name: "linux/query-denied", platform: "linux", inventory: []string{attribute}, queryErr: denied, want: denied, calls: []string{"inventory", attribute}},
		{name: "linux/query-eperm", platform: "linux", inventory: []string{attribute}, queryErr: notPermitted, want: notPermitted, calls: []string{"inventory", attribute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			err := checkPlatformAttribute(context.Background(), tc.platform, func() ([]string, error) {
				calls = append(calls, "inventory")
				return tc.inventory, tc.listErr
			}, func(name string) (int, bool, error) {
				calls = append(calls, name)
				return tc.size, tc.present, tc.queryErr
			})
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(calls, tc.calls) {
				t.Fatalf("error=%v calls=%v; want error=%v calls=%v", err, calls, tc.want, tc.calls)
			}
		})
	}
}

func TestPlatformAttributeCancelledBeforeAccess(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := checkPlatformAttribute(ctx, platform, func() ([]string, error) {
				t.Fatal("cancelled query enumerated attributes")
				return nil, nil
			}, func(string) (int, bool, error) {
				t.Fatal("cancelled query read an attribute")
				return 0, false, nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
