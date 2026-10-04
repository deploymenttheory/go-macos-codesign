package acceptance

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows requires an explicit sparse attribute before extending a new file.
// Match the native capture recipe without physically allocating its zero extent.
// This uses the same test-fixture operation as APFS's replacement sparse tests.
func prepareSparseFixture(file *os.File) error {
	handle := windows.Handle(file.Fd())
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil); err != nil {
		return fmt.Errorf("mark fixture sparse: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("check sparse fixture: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		return fmt.Errorf("fixture is not sparse: attributes %#x", info.FileAttributes)
	}
	return nil
}
