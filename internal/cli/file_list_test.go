package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestFileListOptions(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		destination string
	}{
		{[]string{"-d", "--file-list", "-", "input"}, "-"},
		{[]string{"-d", "--file-list=", "input"}, ""},
		{[]string{"-d", "--file-list=first", "--file-list=last", "input"}, "last"},
	} {
		o, err := parse(tc.args)
		if err != nil || !o.fileList || o.fileListPath != tc.destination || !reflect.DeepEqual(o.paths, []string{"input"}) {
			t.Fatal(o, err)
		}
	}
	if _, err := parse([]string{"-d", "--file-list"}); err == nil {
		t.Fatal("accepted absent argument")
	}
}

func TestFileListJSONAndUnsupported(t *testing.T) {
	path := file(t, "adhoc-arm64")
	destination := filepath.Join(t.TempDir(), "list")
	out, stderr, code := invoke(t, "-d", "--json", "--file-list="+destination, path)
	if code != 0 || stderr != "" || !strings.Contains(out, `"Architectures"`) {
		t.Fatal(out, stderr, code)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(readCLIFile(t, destination)) != resolved+"\n" {
		t.Fatal("wrong JSON companion list")
	}
	before := readCLIFile(t, path)
	if _, stderr, code := invoke(t, "--remove-signature", "--file-list=-", path); code != 1 || !strings.Contains(stderr, "unsupported operation") {
		t.Fatal(code, stderr)
	}
	if !bytes.Equal(before, readCLIFile(t, path)) {
		t.Fatal("unsupported removal mutated input")
	}
	if _, _, code := invoke(t, "-d", "--json", "--file-list=-", "-a", "absent", path); code != 1 {
		t.Fatal(code)
	}
	unsigned := file(t, "unsigned-arm64")
	if _, stderr, code := invoke(t, "-s", "-", "--dryrun", "--file-list=-", unsigned); code != 1 || !strings.Contains(stderr, codesign.ErrUnsigned.Error()) {
		t.Fatal(stderr, code)
	}
	if !bytes.Equal(readCLIFile(t, unsigned), readCLIFile(t, "../../testdata/macho/unsigned-arm64")) {
		t.Fatal("unsigned dry run mutated input")
	}
}

type fileListFailWriter struct{}

func (fileListFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestFileListWriteError(t *testing.T) {
	report, err := codesign.Inspect(context.Background(), file(t, "adhoc-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	err = outputFileList(fileListFailWriter{}, report, options{fileListPath: "-"})
	var output *outputFileError
	if !errors.As(err, &output) || !errors.Is(err, io.ErrClosedPipe) || !strings.HasPrefix(err.Error(), "-: ") {
		t.Fatal(err)
	}
	if err = outputFileList(io.Discard, report, options{fileListPath: "bad\x00"}); err == nil {
		t.Fatal("accepted invalid destination")
	}
	if err = outputFileList(io.Discard, report, options{fileListPath: ""}); !errors.Is(err, os.ErrNotExist) && err.Error() != "No such file or directory" {
		t.Fatal(err)
	}
}
