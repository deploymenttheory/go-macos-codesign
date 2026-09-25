package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const entitlementXMLHeader = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">`

func TestEntitlementWriterFailure(t *testing.T) {
	path := file(t, "unsigned-arm64")
	if err := codesign.Sign(context.Background(), path, codesign.SignOptions{Entitlements: []byte(`<plist><dict><key>test</key><true/></dict></plist>`)}); err != nil {
		t.Fatal(err)
	}
	report, err := codesign.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := extractEntitlements(failWriter{}, &stderr, report, &options{entitlements: "-"}); err == nil {
		t.Fatal("write failure ignored")
	}
	for _, op := range []string{"-d", "--verify", "--remove-signature"} {
		out, stderr, code := invoke(t, op, "--entitlements=", path)
		if code != 1 || out != "" || stderr != "Missing entitlements file path\n" {
			t.Fatal(code, out, stderr)
		}
	}
}
