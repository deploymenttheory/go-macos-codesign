package codesign

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openResourceFile(root *os.Root, name string) (*os.File, error) {
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	base, err := windows.NewNTUnicodeString(filepath.Base(name))
	if err != nil {
		return nil, err
	}
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var openErr error
	err = conn.Control(func(fd uintptr) {
		attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(fd), ObjectName: base, Attributes: windows.OBJ_DONT_REPARSE}
		var status windows.IO_STATUS_BLOCK
		openErr = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
			windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_NON_DIRECTORY_FILE, 0, 0)
		var nativeStatus windows.NTStatus
		if errors.As(openErr, &nativeStatus) {
			openErr = nativeStatus.Errno()
		}
	})
	runtime.KeepAlive(base)
	if err = errors.Join(err, openErr); err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(handle), name), nil
}
