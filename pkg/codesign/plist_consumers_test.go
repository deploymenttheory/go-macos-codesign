package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlistMetadataResourceBoundary(t *testing.T) {
	// Info.plist and CodeResources require their metadata acquisition policy even
	// when their paths are under a resource directory. Ordinary data may use the
	// held-resource fallback after a pathname-attribute denial.
	for _, layout := range []struct {
		name, base, info, main string
		framework              bool
	}{
		{"app", "Contents/", "Contents/Info.plist", "Contents/MacOS/tool", false},
		{"flat-framework", "", "Resources/Info.plist", "Tool", true},
		{"framework", "Versions/A/", "Versions/A/Resources/Info.plist", "Versions/A/Tool", true},
	} {
		t.Run(layout.name, func(t *testing.T) {
			b := &appBundle{base: layout.base, infoPath: layout.info, executable: layout.main, framework: layout.framework}
			for _, name := range []string{layout.info, layout.main, b.resourcesPath(), layout.base + "Resources", layout.base + "Resources-other/data"} {
				if b.ordinarySigningResource(name) {
					t.Fatal("metadata/nonresource received ordinary fallback", name)
				}
			}
			for _, name := range []string{"Resources/data", "Resources/nested/Info.plist"} {
				if !b.ordinarySigningResource(layout.base + name) {
					t.Fatal("ordinary resource lost fallback", name)
				}
			}
			for _, name := range []string{"Headers/api.h", "PrivateHeaders/private.h", "Modules/module.modulemap"} {
				if b.ordinarySigningResource(layout.base+name) != layout.framework {
					t.Fatal("framework resource policy changed", name)
				}
			}
		})
	}
}

func TestPlistEnvelopeWriteFailures(t *testing.T) {
	app := testBundle(t)
	original := encodeBundleResources(map[string]any{}, map[string]any{})
	bundleFile(t, app, bundleResourcesPath, original)
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.write(ctx, bundleResourcesPath, []byte("changed"), true); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if !bytes.Equal(original, readTestFile(t, filepath.Join(app, bundleResourcesPath))) {
		t.Fatal("canceled write changed envelope")
	}
	b.close()
	if err := b.write(context.Background(), bundleResourcesPath, []byte("changed"), true); err == nil {
		t.Fatal("closed root permitted envelope write")
	}
	if !bytes.Equal(original, readTestFile(t, filepath.Join(app, bundleResourcesPath))) {
		t.Fatal("closed-root write changed envelope")
	}
	if _, err := os.Stat(filepath.Join(app, bundleResourcesPath)); err != nil {
		t.Fatal("lost original envelope", err)
	}
}

func TestEntitlementPlistConsumerTypes(t *testing.T) {
	// Typed decoding remains separate from the native bundle interpreter: only
	// actual booleans may grant execution flags, never strings or integers.
	for _, tc := range []struct {
		value string
		want  uint64
	}{
		{"<true/>", 0x10}, {"<false/>", 0}, {"<integer>1</integer>", 0}, {"<string>true</string>", 0},
	} {
		data := []byte(`<plist><dict><key>get-task-allow</key>` + tc.value + `</dict></plist>`)
		xml, _, err := EncodeEntitlements(data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, xml) || entitlementExecFlags(xml) != tc.want {
			t.Fatal("changed bytes or entitlement type", tc.value)
		}
	}
	if _, _, err := EncodeEntitlements([]byte(`<plist/>`)); !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "dictionary") {
		t.Fatal("missing root accepted", err)
	}
}
