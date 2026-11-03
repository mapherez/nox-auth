//go:build linux || darwin

package auth

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type LocalListener struct {
	net.Listener
	lock *os.File
}

func ListenLocal(directory, name string) (*LocalListener, error) {
	if e := os.MkdirAll(directory, 03770); e != nil {
		return nil, e
	}
	path := filepath.Join(directory, name)
	if len(path) > 100 {
		return nil, fmt.Errorf("Unix socket path is too long; configure a shorter socket directory")
	}
	lock, e := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("another Auth instance owns this local socket")
	}
	fail := func(e error) (*LocalListener, error) { lock.Close(); return nil, e }
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fail(errors.New("refusing to replace a non-socket at Auth socket path"))
		}
		if e = os.Remove(path); e != nil {
			return fail(e)
		}
	} else if !os.IsNotExist(e) {
		return fail(e)
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return fail(e)
	}
	if e = os.Chmod(path, 0660); e != nil {
		listener.Close()
		return fail(e)
	}
	return &LocalListener{listener, lock}, nil
}
func (l *LocalListener) Close() error { e := l.Listener.Close(); _ = l.lock.Close(); return e }

func lockData(directory string) (*os.File, error) {
	f, e := os.OpenFile(filepath.Join(directory, "auth.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another Auth process owns this data directory")
	}
	return f, nil
}
