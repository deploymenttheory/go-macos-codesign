//go:build darwin || linux

package codesign

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openResourceFile(root *os.Root, name string) (*os.File, error) {
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var openErr error
	err = conn.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), filepath.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: openErr}
	}
	return os.NewFile(uintptr(fd), name), nil
}
