package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func outputFileList(stdout io.Writer, report *codesign.Report, o options) error {
	files, err := report.SignatureFiles(o.architecture)
	if err != nil {
		return err
	}
	contents := strings.Join(files, "\n") + "\n"
	if o.fileListPath == "-" {
		_, err = io.WriteString(stdout, contents)
	} else {
		var out *os.File
		out, err = os.OpenFile(o.fileListPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			_, err = io.WriteString(out, contents)
			closeErr := out.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		return &fileListOutputError{o.fileListPath, certificateOutputError(o.fileListPath, err)}
	}
	return nil
}

// File-list errors name the output destination, unlike certificate extraction.
// An empty destination uses perror's message-only spelling.
type fileListOutputError struct {
	path string
	err  error
}

func (e *fileListOutputError) Error() string {
	if e.path == "" {
		return e.err.Error()
	}
	return fmt.Sprintf("%s: %s", e.path, e.err)
}
func (e *fileListOutputError) Unwrap() error { return e.err }
