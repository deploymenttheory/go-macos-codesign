package codesign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneAliasReportsAndFailurePreservation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target, alias := filepath.Join(dir, "physical"), filepath.Join(dir, "alias")
	input := fixture(t, "adhoc-arm64")
	if err := os.WriteFile(target, input, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("physical", alias); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, inspect := range []func() (*Report, error){
		func() (*Report, error) { return Inspect(ctx, alias) },
		func() (*Report, error) { return Verify(ctx, alias, VerifyOptions{}) },
	} {
		r, err := inspect()
		if err != nil || r.Path != want || r.Bundle != nil {
			t.Fatalf("report must identify physical standalone file: %+v %v", r, err)
		}
	}
	if err := Sign(ctx, alias, SignOptions{}); !errors.Is(err, ErrSigned) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := Sign(canceled, alias, SignOptions{Force: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := RemoveSignature(canceled, alias); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !bytes.Equal(input, readTestFile(t, target)) {
		t.Fatal("failed alias operation modified target")
	}
	if got, err := os.Readlink(alias); err != nil || got != "physical" {
		t.Fatal("failed operation changed alias", got, err)
	}
}

func TestStandaloneAliasErrors(t *testing.T) {
	for _, kind := range []string{"broken", "loop", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			alias, target := filepath.Join(dir, "alias"), filepath.Join(dir, "target")
			destination := "target"
			if kind == "loop" {
				destination = "alias"
			}
			if kind == "malformed" {
				if err := os.WriteFile(target, []byte("not executable"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(destination, alias); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			for _, op := range []func() error{
				func() error { return Sign(ctx, alias, SignOptions{}) },
				func() error { return RemoveSignature(ctx, alias) },
				func() error { _, err := Inspect(ctx, alias); return err },
				func() error { _, err := Verify(ctx, alias, VerifyOptions{}); return err },
			} {
				if err := op(); err == nil {
					t.Fatal("accepted invalid target")
				}
				if got, err := os.Readlink(alias); err != nil || got != destination {
					t.Fatal("changed alias on failure", got, err)
				}
				if kind == "malformed" && string(readTestFile(t, target)) != "not executable" {
					t.Fatal("changed invalid file")
				}
			}
		})
	}
}

func TestStandalonePathAST(t *testing.T) {
	var record struct {
		Targets map[string]map[string]struct {
			References map[string]int
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../spec/apple-paths.json"), &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Targets) != 2 {
		t.Fatal("both path AST targets required")
	}
	for target, facts := range record.Targets {
		if len(facts) != 8 || facts["cleanPath"].References["realpath"] != 1 || facts["staticCodePath"].References["cleanPath"] != 1 || facts["staticCodePath"].References["SecStaticCodeCreateWithPathAndAttributes"] != 1 || facts["recommendedIdentifier"].References["canonicalIdentifier"] != 1 || facts["note"].References["vfprintf"] != 1 || facts["note"].References["fprintf"] != 1 || facts["note"].References["verbose"] != 1 || facts["certificates"].References["validateDirectory"] != 1 || facts["signature"].References["take"] != 1 {
			t.Fatalf("missing path resolution/identifier control flow for %s: %+v", target, facts)
		}
	}
}
