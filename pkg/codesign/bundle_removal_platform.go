package codesign

import (
	"errors"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Discovery, acquisition and dictionary parsing are separate decisions. An
// acquired empty platform plist retains its URL; a failed data read falls back.
func (b *appBundle) removalInfo() ([]byte, bool, error) {
	platform := strings.TrimSuffix(b.infoPath, ".plist") + "-macos.plist"
	kind, err := hostdata.ReadEntryType(b.root, platform)
	if errors.Is(err, os.ErrPermission) {
		return nil, false, verificationFailure("bundle format is ambiguous (could be app or framework)", err)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err == nil && kind != os.ModeDir {
		if kind != 0 {
			return nil, false, unsupported("non-regular platform plist: " + platform)
		}
		file, openErr := hostdata.OpenContentFileRead(b.root, platform)
		if openErr == nil {
			data, readErr := readBounded(file, maxBundlePlist)
			closeErr := file.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return nil, false, err
			}
			b.infoPath = platform
			return data, true, nil
		}
		if !errors.Is(openErr, os.ErrPermission) && !errors.Is(openErr, os.ErrNotExist) {
			return nil, false, openErr
		}
	}
	data, err := b.read(b.infoPath, maxBundlePlist)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
}
