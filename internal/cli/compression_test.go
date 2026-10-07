package cli

import (
	"bytes"
	"os"
	"testing"
)

func TestPreserveAFSCOption(t *testing.T) {
	if _, err := parse([]string{"--preserve-afsc=value", "-d", "file"}); err == nil {
		t.Fatal("accepted argument for flag")
	}
	for _, operation := range []string{"display", "verify", "sign", "dryrun", "remove"} {
		t.Run(operation, func(t *testing.T) {
			path := file(t, "adhoc-arm64")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--preserve-afsc"}
			switch operation {
			case "display":
				args = append(args, "-d")
			case "verify":
				args = append(args, "--verify")
			case "remove":
				args = append(args, "--remove-signature")
			default:
				args = append(args, "-f", "-s", "-", "-i", "org.example.compression", "--timestamp=none")
				if operation == "dryrun" {
					args = append(args, "--dryrun")
				}
			}
			_, diagnostic, code := invoke(t, append(args, path)...)
			if code != 0 {
				t.Fatal(code, diagnostic)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "display" || operation == "verify" || operation == "dryrun" {
				if !bytes.Equal(before, after) {
					t.Fatal("nonmutating operation changed payload")
				}
			} else if bytes.Equal(before, after) {
				t.Fatal("mutation did not occur")
			}
		})
	}
}
