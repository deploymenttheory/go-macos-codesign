package codesign

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
)

const resourceDiagnostic = "a sealed resource is missing or invalid"

func resourceFailure(kind, name string, opts VerifyOptions) error {
	err := &VerificationError{Diagnostic: resourceDiagnostic, cause: invalid("%s resource: %s", kind, name), resourceFailure: true}
	path := filepath.Join(opts.resourceBase, name)
	switch kind {
	case "added":
		err.AddedResources = []string{path}
	case "modified":
		err.ModifiedResources = []string{path}
	case "missing":
		err.MissingResources = []string{path}
	}
	return err
}

type resourceFailures struct {
	detail VerificationError
	causes []error
}

// Apple collects local resource failures, but propagates nested exceptions.
// Its workers race to append details. Portable output uses a stable path order.
func (f *resourceFailures) collect(err error) bool {
	var detail *VerificationError
	if !errors.As(err, &detail) || !detail.resourceFailure || detail.Subcomponent != "" {
		return false
	}
	if len(f.causes) == 0 {
		f.detail.Diagnostic = detail.Diagnostic
		f.detail.resourceFailure = true
	}
	f.causes = append(f.causes, err)
	f.detail.AddedResources = append(f.detail.AddedResources, detail.AddedResources...)
	f.detail.ModifiedResources = append(f.detail.ModifiedResources, detail.ModifiedResources...)
	f.detail.MissingResources = append(f.detail.MissingResources, detail.MissingResources...)
	return true
}

func (f *resourceFailures) err() error {
	if len(f.causes) == 0 {
		return nil
	}
	sort.Strings(f.detail.AddedResources)
	sort.Strings(f.detail.ModifiedResources)
	sort.Strings(f.detail.MissingResources)
	f.detail.cause = errors.Join(f.causes...)
	return &f.detail
}

func verifyBundleResource(ctx context.Context, name string, seal, actual any, present bool, opts VerifyOptions) error {
	value, ok := seal.(map[string]any)
	include, optional := resourcePolicy(name, false)
	if _, nested := value["requirement"]; nested {
		if _, err := nestedRequirement(name, seal); err != nil {
			return err
		}
		if !present {
			return resourceFailure("missing", name, opts)
		}
		switch child := actual.(type) {
		case *nestedAppResource:
			return verifyNestedApp(ctx, name, seal, child, opts)
		case nestedResource:
			return verifyNestedResource(ctx, name, seal, child, opts)
		default:
			return resourceFailure("modified", name, opts)
		}
	}
	if target, linked := value["symlink"].(string); linked {
		if !include || target == "" || !reflect.DeepEqual(seal, symlinkSeal(target, optional)) {
			return invalid("symlink resource seal: %s", name)
		}
	} else {
		hash, hashOK := value["hash2"].([]byte)
		if !include || !ok || !hashOK || len(hash) != 32 || !reflect.DeepEqual(seal, resourceSeal(hash, optional, false)) {
			return invalid("resource seal for %s", name)
		}
	}
	if present {
		if !reflect.DeepEqual(actual, seal) {
			return resourceFailure("modified", name, opts)
		}
		if target, linked := value["symlink"].(string); linked && opts.StrictSymlinks && !opts.NoStrict {
			return verifyStrictLink(name, target, opts)
		}
	} else if !optional {
		return resourceFailure("missing", name, opts)
	}
	return nil
}
