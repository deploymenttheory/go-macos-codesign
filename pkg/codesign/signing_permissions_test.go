package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type deniedFinderCarrier struct {
	*signingCarrier
	failure error
}

func (c *deniedFinderCarrier) RemoveAttribute(ctx context.Context, name string) error {
	if name == appledouble.FinderInfoName {
		return c.failure
	}
	return c.signingCarrier.RemoveAttribute(ctx, name)
}

// These failures use the explicit carrier protocol on every OS. They prove the
// same permission/cancellation policy and partial metadata mutation independently
// of the host's different ACL models and attribute namespaces.
func TestSigningPermissionPartialRemoval(t *testing.T) {
	for _, shape := range []string{"standalone", "main", "resource", "child"} {
		for _, failure := range []error{syscall.EACCES, syscall.EPERM, context.Canceled, context.DeadlineExceeded} {
			t.Run(shape+"/"+failure.Error(), func(t *testing.T) {
				operand := filepath.Join(t.TempDir(), "tool")
				target := operand
				if shape == "standalone" {
					if err := os.WriteFile(operand, fixture(t, "unsigned-arm64"), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					operand = testBundle(t)
					bundleFile(t, operand, "Contents/Resources/data", []byte("resource"))
					target = filepath.Join(operand, "Contents/MacOS/hello")
					if shape == "resource" {
						target = filepath.Join(operand, "Contents/Resources/data")
					}
					if shape == "child" {
						target = filepath.Join(nestedApp(t, operand, "Contents/PlugIns/Child.app"), "Contents/MacOS/hello")
					}
				}
				before := readTestFile(t, target)
				carrier := &deniedFinderCarrier{signingCarrier: &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{ResourceFork: []byte("fork"), FinderInfo: [32]byte{1}, Attrs: []appledouble.Attr{{Name: "user.control", Value: []byte("keep")}}})}, failure: failure}
				opts := SignOptions{Force: true, Deep: true, StripDisallowedXattrs: true}
				if shape == "standalone" {
					opts.AppleDouble = carrier
				} else {
					opts.AppleDoubleFiles = map[string]appledouble.Value{target: carrier}
				}
				err := Sign(context.Background(), operand, opts)
				if !errors.Is(err, failure) {
					t.Fatalf("lost underlying error: %v", err)
				}
				if !bytes.Equal(before, readTestFile(t, target)) {
					t.Fatal("failed target was rewritten")
				}
				f, decodeErr := appledouble.DecodeStream(context.Background(), carrier, appledouble.DefaultStreamLimits())
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				if f.ResourceFork != nil && f.ResourceFork.Size() != 0 || f.FinderInfo != [32]byte{1} || len(f.Attrs) != 1 || f.Attrs[0].Name != "user.control" {
					t.Fatal("partial removal was lost or unrelated metadata changed")
				}
				control := make([]byte, 4)
				if _, err := f.Attrs[0].Value.ReadAt(control, 0); err != nil && !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
				if string(control) != "keep" {
					t.Fatal("control changed")
				}
				if errors.Is(failure, os.ErrPermission) {
					var detail *VerificationError
					if !errors.As(err, &detail) {
						t.Fatalf("missing diagnostic: %v", err)
					}
					want := "Permission denied"
					if errors.Is(failure, syscall.EPERM) {
						want = "Operation not permitted"
					}
					if detail.Diagnostic != want {
						t.Fatal(detail)
					}
					child, pathErr := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(filepath.Dir(target))))
					if pathErr != nil {
						t.Fatal(pathErr)
					}
					if shape == "child" && detail.Subcomponent != child {
						t.Fatalf("wrong child: %s", detail.Subcomponent)
					}
				}
			})
		}
	}
}

func TestSigningPermissionDiagnosticIdentity(t *testing.T) {
	detail := &VerificationError{Diagnostic: "existing", cause: syscall.EACCES}
	for _, err := range []error{nil, detail, context.Canceled, context.DeadlineExceeded, os.ErrNotExist, fmt.Errorf("joined: %w", errors.Join(context.Canceled, syscall.EACCES))} {
		if signingIOError(err) != err { //nolint:errorlint // Assert preservation of the original error object, not merely its cause.
			t.Fatalf("replaced qualified/nonpermission error: %v", err)
		}
	}
	failure := errors.Join(hostdata.ErrXattrNotFound, io.ErrUnexpectedEOF)
	var diagnostic *VerificationError
	if err := signingIOError(failure); !errors.As(err, &diagnostic) || diagnostic.Diagnostic != "Attribute not found" || !errors.Is(err, failure) {
		t.Fatal("attribute error lost its native diagnostic or underlying causes", err)
	}
}

func TestSigningResourceAcquisition(t *testing.T) {
	app := testBundle(t)
	bundleFile(t, app, "Contents/Resources/data", []byte("resource"))
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	for _, name := range []string{"Contents/Resources/data", "Contents/Resources", "missing", "missing/child", "../outside"} {
		info, err := b.resourceInfo(name)
		if name == "Contents/Resources/data" {
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal(info, err)
			}
		} else if err == nil {
			t.Fatalf("accepted nonresource %s", name)
		}
	}
	link := filepath.Join(app, "Contents/Resources/link")
	if err := os.Symlink("data", link); err != nil {
		t.Fatal(err)
	}
	if _, err := b.resourceInfo("Contents/Resources/link"); err == nil {
		t.Fatal("followed resource link during acquisition")
	}
	walk := signingBundleWalker{b}
	for _, name := range []string{"missing", "Contents/Resources/data"} {
		if _, err := walk.ReadDir(name); err == nil {
			t.Fatal("enumerated non-directory", name)
		}
	}
	entries, err := walk.ReadDir("Contents/Resources")
	if err != nil || len(entries) == 0 {
		t.Fatal(entries, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.signingExecutable(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	b.executable = "missing"
	if _, err := b.signingExecutable(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	b.close()
	if _, err := walk.ReadDir("."); err == nil {
		t.Fatal("enumerated closed root")
	}
}
