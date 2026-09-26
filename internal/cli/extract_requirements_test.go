package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestRequirementWriterFailure(t *testing.T) {
	path := file(t, "unsigned-arm64")
	if e := codesign.Sign(context.Background(), path, codesign.SignOptions{}); e != nil {
		t.Fatal(e)
	}
	report, e := codesign.Inspect(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	e = extractRequirements(failWriter{}, report, options{requirements: "-"})
	var output *outputFileError
	if !errors.As(e, &output) {
		t.Fatal("writer error lost", e)
	}
	if e = extractRequirements(failWriter{}, report, options{requirements: "-", architecture: "missing"}); e == nil {
		t.Fatal("selection error lost")
	}
	if _, _, code := invoke(t, "--remove-signature", "-r=always", path); code != 1 {
		t.Fatal("unsupported removal accepted", code)
	}
}
