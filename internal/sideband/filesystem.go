package sideband

import (
	"context"
	"os"
	"runtime"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// The SDK owns filesystem dispatch and held-object association. The policy
// layer neither chooses a carrier pathname nor remaps attribute namespaces.
type filesystemQueries struct {
	view *hostdata.FilesystemMetadata
	ctx  context.Context
}

func openFilesystemQueries(ctx context.Context, file *os.File) (*filesystemQueries, error) {
	view, err := hostdata.FilesystemMetadataForFile(ctx, file)
	if err != nil {
		return nil, err
	}
	return &filesystemQueries{view: view, ctx: ctx}, nil
}
func (q *filesystemQueries) list() ([]string, error) {
	return q.view.List(q.ctx, hostdata.MaxXattrListSize)
}
func (q *filesystemQueries) size(name string) (int, bool, error) {
	size, present, err := q.view.Size(q.ctx, name)
	// Policy only needs empty/nonempty, but keep representable lengths intact.
	return int(min(size, int64(int(^uint(0)>>1)))), present, err
}
func (q *filesystemQueries) remove(name string) error {
	// Native FileDesc::removeAttr accepts an already-absent value as success.
	_, err := q.view.Remove(q.ctx, name)
	return err
}
func (q *filesystemQueries) platform() string {
	if q.view.UsesAppleDouble() {
		return "appledouble"
	}
	return runtime.GOOS
}
