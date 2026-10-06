package codesign

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func prepareCommandSparseFixture(file *os.File) error {
	handle := windows.Handle(file.Fd())
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil); err != nil {
		return fmt.Errorf("mark command fixture sparse: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		return fmt.Errorf("command fixture is not sparse")
	}
	return nil
}
