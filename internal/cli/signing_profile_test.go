package cli

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestSigningHostProfile(t *testing.T) {
	for _, major := range []uint32{15, 26, 27} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			got, err := signingHostProfile(t.Context(), func(ctx context.Context) (osversion.Version, error) {
				if ctx != t.Context() {
					t.Fatal("lost context")
				}
				return osversion.Version{Major: major}, nil
			})
			if err != nil || uint32(got) != major {
				t.Fatal(got, err)
			}
		})
	}
	for _, failure := range []error{errors.ErrUnsupported, context.Canceled, osversion.ErrMacOSProfile} {
		got, err := signingHostProfile(t.Context(), func(context.Context) (osversion.Version, error) { return osversion.Version{}, failure })
		if errors.Is(failure, errors.ErrUnsupported) {
			if got != osversion.MacOS27 || err != nil {
				t.Fatal(got, err)
			}
		} else if got != 0 || !errors.Is(err, failure) {
			t.Fatal(got, err)
		}
	}
	if _, err := signingHostProfile(t.Context(), func(context.Context) (osversion.Version, error) { return osversion.Version{Major: 99}, nil }); !errors.Is(err, osversion.ErrMacOSProfile) {
		t.Fatal(err)
	}
}
