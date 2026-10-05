package codesign

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestVerificationLinkTextAndBudget(t *testing.T) {
	for _, target := range []string{"absent", "link", "../../../outside", "/System/Library/file", "sub//file", "bad:name", "."} {
		t.Run(target, func(t *testing.T) {
			bundle := testBundle(t)
			bundleLink(t, bundle, "Contents/Resources/link", target)
			b, err := openAppBundle(bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			actual, err := os.Readlink(filepath.Join(bundle, "Contents/Resources/link"))
			if err != nil {
				t.Fatal(err)
			}
			scope := newBundleScan()
			scope.verifyLinks = true
			got, err := b.resourceLink("Contents/Resources/link", "Resources/link", scope)
			if err != nil || got != filepath.ToSlash(actual) || scope.bytes != int64(len(got)) {
				t.Fatal(got, scope.bytes, err)
			}
			scope.bytes = maxFileSize
			if _, err = b.resourceLink("Contents/Resources/link", "Resources/link", scope); err != nil || scope.bytes != maxFileSize+int64(len(got)) {
				t.Fatal("link rejected legacy aggregate boundary", scope.bytes, err)
			}
			scope.bytes = math.MaxInt64
			if _, err = b.resourceLink("Contents/Resources/link", "Resources/link", scope); !errors.Is(err, ErrUnsupported) {
				t.Fatal("missing verification overflow check", err)
			}
		})
	}
}
