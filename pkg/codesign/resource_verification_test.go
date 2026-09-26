package codesign

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResourceFailureCollection(t *testing.T) {
	base := t.TempDir()
	original := resourceSeal(make([]byte, 32), false, false)
	changed := resourceSeal([]byte(strings.Repeat("x", 32)), false, false)
	sealed := map[string]any{"Resources/a": original, "Resources/b": original, "Resources/c": original, "Resources/fr.lproj/optional": resourceSeal(make([]byte, 32), true, false)}
	actual := map[string]any{"Resources/b": changed, "Resources/c": changed, "Resources/z": original, "Resources/y": original}
	data := encodeBundleResources(map[string]any{}, sealed)
	for i := 0; i < 20; i++ {
		count, err := verifyBundleResourcesWithOptions(context.Background(), data, actual, VerifyOptions{resourceBase: base})
		var detail *VerificationError
		if count != 0 || !errors.Is(err, ErrInvalid) || !errors.As(err, &detail) || detail.Diagnostic != resourceDiagnostic || detail.Architecture != "" || detail.Subcomponent != "" {
			t.Fatal(count, detail, err)
		}
		for _, group := range []struct {
			got   []string
			names []string
		}{{detail.AddedResources, []string{"y", "z"}}, {detail.ModifiedResources, []string{"b", "c"}}, {detail.MissingResources, []string{"a"}}} {
			var want []string
			for _, name := range group.names {
				want = append(want, filepath.Join(base, "Resources", name))
			}
			if !reflect.DeepEqual(group.got, want) {
				t.Fatal(group.got, want)
			}
		}
		for _, part := range []string{"modified resource: Resources/b", "modified resource: Resources/c", "added resource: Resources/y", "added resource: Resources/z", "missing resource: Resources/a"} {
			if !strings.Contains(err.Error(), part) {
				t.Fatal("lost cause", err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifyBundleResourcesWithOptions(ctx, data, actual, VerifyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := verifyBundleResources(data, map[string]any{"../outside": true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unvalidated added path", err)
	}
}

func TestResourceCollectionBoundaries(t *testing.T) {
	var collected resourceFailures
	if collected.err() != nil || collected.collect(context.Canceled) || collected.collect(invalid("malformed seal")) {
		t.Fatal("collected non-resource error")
	}
	first := resourceFailure("modified", "Resources/a", VerifyOptions{})
	second := resourceFailure("missing", "Resources/b", VerifyOptions{})
	if !collected.collect(first) || !collected.collect(second) {
		t.Fatal("resource rejected")
	}
	err := collected.err()
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatal("lost causes", err)
	}
	nested := nestedVerificationError("child", err)
	if collected.collect(nested) {
		t.Fatal("swallowed child exception")
	}
	var parent resourceFailures
	sealed := nestedVerificationError("Helpers/tool", ErrRequirement)
	if !parent.collect(sealed) {
		t.Fatal("parent seal not collected")
	}
	if !errors.Is(parent.err(), ErrInvalid) || errors.Is(parent.err(), ErrRequirement) {
		t.Fatal(parent.err())
	}
	seal := map[string]any{"requirement": "always"}
	for _, actual := range []any{nil, symlinkSeal("target", false), resourceSeal(make([]byte, 32), false, false)} {
		err := verifyBundleResource(context.Background(), "Helpers/tool", seal, actual, actual != nil, VerifyOptions{})
		var detail *VerificationError
		if !errors.Is(err, ErrInvalid) || !errors.As(err, &detail) || (len(detail.MissingResources) == 1) != (actual == nil) {
			t.Fatal(detail, err)
		}
	}
	if err := verifyBundleResource(context.Background(), "Helpers/tool", map[string]any{"requirement": false}, nil, false, VerifyOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid nested seal", err)
	}
}
