package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signedNested(t *testing.T, arch string, opts SignOptions) []byte {
	t.Helper()
	if opts.Identifier == "" {
		opts.Identifier = "org.example.child"
	}
	data, err := SignBytes(context.Background(), fixture(t, "unsigned-"+arch), opts)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNestedSeals(t *testing.T) {
	ctx := context.Background()
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			data := signedNested(t, arch, SignOptions{})
			seal, err := nestedSeal(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, deep := range []bool{false, true} {
				if err := verifyNestedResource(ctx, "helper", seal, nestedResource{data}, VerifyOptions{Deep: deep}); err != nil {
					t.Fatal(err)
				}
			}
			c, err := parseContainer(data)
			if err != nil {
				t.Fatal(err)
			}
			data[int(c.slices[0].offset)+4096] ^= 1
			if err := verifyNestedResource(ctx, "helper", seal, nestedResource{data}, VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := verifyNestedResource(ctx, "helper", seal, nestedResource{data}, VerifyOptions{Deep: true}); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
	data := signedNested(t, "arm64", SignOptions{})
	seal, _ := nestedSeal(data)
	for _, bad := range []any{nil, true, map[string]any{}, map[string]any{"requirement": ""}, map[string]any{"requirement": "always", "cdhash": []byte{1}}, map[string]any{"requirement": "always", "extra": true}, map[string]any{"requirement": "always", "cdhash": make([]byte, 20), "extra": true}, map[string]any{"requirement": "never"}} {
		if err := verifyNestedResource(ctx, "helper", bad, nestedResource{data}, VerifyOptions{}); err == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	delete(seal, "cdhash") // Native uses the requirement; cdhash is optional metadata.
	if err := verifyNestedResource(ctx, "helper", seal, nestedResource{data}, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, fixture(t, "unsigned-arm64"), testDMG(t)} {
		if _, err := nestedSeal(bad); err == nil {
			t.Fatal("invalid child sealed")
		}
		if err := verifyNestedResource(ctx, "helper", seal, nestedResource{bad}, VerifyOptions{}); err == nil {
			t.Fatal("invalid child verified")
		}
	}
	// A SHA-1-only directory is outside this phase's nested profile.
	r, _ := InspectBytes(data)
	off := int(r.Architectures[0].SignatureOffset)
	cd := int(be.Uint32(data[off+16:])) + off
	data[cd+37] = 1
	data[cd+36] = 20
	if _, err := nestedSeal(data); err == nil {
		t.Fatal("SHA-1 nested seal accepted")
	}
}

func TestNestedCertificateTrust(t *testing.T) {
	ctx := context.Background()
	for _, algorithm := range []string{"rsa", "p256"} {
		id := testIdentity(t, algorithm)
		data := signedNested(t, "universal", SignOptions{Identity: id})
		seal, err := nestedSeal(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, deep := range []bool{false, true} {
			if err := verifyNestedResource(ctx, "child", seal, nestedResource{data}, VerifyOptions{Deep: deep}); err == nil {
				t.Fatal("untrusted nested certificate accepted")
			}
			if err := verifyNestedResource(ctx, "child", seal, nestedResource{data}, VerifyOptions{Deep: deep, TrustedCertificates: id.Certificates}); err != nil {
				t.Fatal(err)
			}
		}
		app := testBundle(t)
		bundleFile(t, app, "Contents/Frameworks/lib.dylib", data)
		if err := Sign(ctx, app, SignOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, app, VerifyOptions{Deep: true, TrustedCertificates: id.Certificates}); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); err == nil {
			t.Fatal("ad-hoc parent bypassed child trust")
		}
	}
}

func TestNestedSigningSafety(t *testing.T) {
	ctx := context.Background()
	for _, problem := range []string{"unsigned", "dryrun", "bad-parent", "bad-options", "malformed-child", "timestamp", "cancelled"} {
		t.Run(problem, func(t *testing.T) {
			app := testBundle(t)
			name := "Contents/Helpers/tool"
			bundleFile(t, app, name, fixture(t, "unsigned-arm64"))
			opts := SignOptions{Deep: true}
			callCtx := ctx
			switch problem {
			case "unsigned":
				opts.Deep = false
			case "dryrun":
				opts.DryRun = true
			case "bad-parent":
				bundleFile(t, app, "Contents/MacOS/hello", []byte("bad"))
			case "bad-options":
				opts.PageSize = 3
			case "malformed-child":
				bundleFile(t, app, name, []byte("not Mach-O"))
			case "timestamp":
				opts.Identity = testIdentity(t, "rsa")
				opts.Timestamp = &TimestampOptions{TrustedRoots: opts.Identity.Certificates, Provider: func(context.Context, []byte) ([]byte, error) { return nil, errors.New("offline") }}
			case "cancelled":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before, _ := os.ReadFile(filepath.Join(app, name))
			if err := Sign(callCtx, app, opts); err == nil {
				t.Fatal("expected failure")
			}
			after, _ := os.ReadFile(filepath.Join(app, name))
			if !bytes.Equal(before, after) {
				t.Fatal("failed signing mutated child")
			}
			if _, err := os.Stat(filepath.Join(app, "Contents/_CodeSignature")); !os.IsNotExist(err) {
				t.Fatal("created envelope directory", err)
			}
		})
	}
	app := testBundle(t)
	for i := 0; i <= maxNestedFiles; i++ {
		bundleFile(t, app, fmt.Sprintf("Contents/Helpers/tool%d", i), fixture(t, "unsigned-arm64"))
	}
	if err := Sign(ctx, app, SignOptions{Deep: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("child limit", err)
	}
}

func TestNestedPathsAndHardlinks(t *testing.T) {
	ctx := context.Background()
	for _, root := range nestedCodeRoots {
		app := testBundle(t)
		bundleFile(t, app, "Contents/"+root+"/group/child", fixture(t, "unsigned-arm64"))
		if err := Sign(ctx, app, SignOptions{Deep: true}); err != nil {
			t.Fatal(root, err)
		}
		if _, err := Verify(ctx, app, VerifyOptions{Deep: true}); err != nil {
			t.Fatal(root, err)
		}
	}
	for _, other := range []string{"Contents/MacOS/hello", "Contents/Resources/alias", "Contents/Frameworks/alias", "Contents/Helpers/alias"} {
		app := testBundle(t)
		if !strings.HasSuffix(other, "/hello") {
			bundleFile(t, app, other, fixture(t, "unsigned-arm64"))
		}
		if err := os.MkdirAll(filepath.Join(app, "Contents/Helpers"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(app, other), filepath.Join(app, "Contents/Helpers/child")); err != nil {
			t.Fatal(err)
		}
		if err := Sign(ctx, app, SignOptions{Deep: true}); !errors.Is(err, ErrUnsupported) {
			t.Fatal("hardlink accepted", err)
		}
	}
}

func TestPrepareNestedFailures(t *testing.T) {
	ctx := context.Background()
	// Native deep signing always replaces linker signatures, even without force.
	linker := signedNested(t, "arm64", SignOptions{Flags: 0x20000})
	writes, err := prepareNested(ctx, map[string]any{"Helpers/tool": nestedResource{linker}}, SignOptions{Deep: true})
	if err != nil || len(writes) != 1 {
		t.Fatal("linker signature was preserved", err)
	}
	r, err := InspectBytes(writes[0].data)
	if err != nil || r.Architectures[0].Signature.Directories[0].Flags&0x20000 != 0 {
		t.Fatal("linker flag retained", err)
	}
	for _, tc := range []struct {
		data []byte
		opts SignOptions
	}{
		{nil, SignOptions{Deep: true}},
		{fixture(t, "unsigned-arm64"), SignOptions{}},
		{fixture(t, "unsigned-arm64"), SignOptions{Deep: true, Identifier: "\x00"}},
	} {
		if _, err := prepareNested(ctx, map[string]any{"Helpers/tool": nestedResource{tc.data}}, tc.opts); err == nil {
			t.Fatal("accepted invalid child")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := prepareNested(cancelled, map[string]any{"Helpers/tool": nestedResource{}}, SignOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNestedSourceAST(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-nested.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]map[string]struct{ Members map[string]int }
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("missing Clang target")
	}
	for target, methods := range facts.Targets {
		for method, members := range map[string][]string{
			"signNested":         {"sign", "designatedRequirement", "cdHash"},
			"sign":               {"isSigned", "flag", "resetValidity"},
			"validateNestedCode": {"requirement", "initializeFromParent", "staticValidate"},
			"identificationFor":  {"findCommand", "header", "loadCommands"},
			"uniqueName":         {"identification"},
		} {
			for _, member := range members {
				if methods[method].Members[member] == 0 {
					t.Fatal(target, method, member)
				}
			}
		}
	}
}
