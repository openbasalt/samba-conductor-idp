// Package sockutil opens the management API's Unix socket (systemd socket
// activation first) and reads a peer's credentials.
package sockutil

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// Listen returns the socket passed by systemd socket activation when
// present (LISTEN_FDS), else creates path with mode 0660 and group (name
// or number; empty keeps the process's group).
func Listen(path, group string) (*net.UnixListener, bool, error) {
	if ln, ok, err := activation(); err != nil || ok {
		return ln, ok, err
	}
	if !filepath.IsAbs(path) {
		return nil, false, errors.New("sockutil: socket path must be absolute")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, false, fmt.Errorf("sockutil: %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, false, fmt.Errorf("sockutil: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if group != "" {
		gid, err := LookupGroup(group)
		if err != nil {
			_ = ln.Close()
			return nil, false, err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return nil, false, fmt.Errorf("sockutil: socket group %s: %w (the service user must be a member)", group, err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, false, err
	}
	return ln, false, nil
}

// activation returns the first socket passed by systemd.
func activation() (*net.UnixListener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, false, nil
	}
	f := os.NewFile(3, "systemd-socket")
	l, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, false, fmt.Errorf("sockutil: socket activation: %w", err)
	}
	ul, ok := l.(*net.UnixListener)
	if !ok {
		_ = l.Close()
		return nil, false, errors.New("sockutil: socket activation passed a non-Unix socket")
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	return ul, true, nil
}

// LookupGroup resolves a group name or number.
func LookupGroup(g string) (int, error) {
	if n, err := strconv.Atoi(g); err == nil {
		return n, nil
	}
	grp, err := user.LookupGroup(g)
	if err != nil {
		return 0, fmt.Errorf("sockutil: group %q: %w", g, err)
	}
	return strconv.Atoi(grp.Gid)
}

// UIDs resolves user names and adds explicit UIDs.
func UIDs(names []string, uids []int) ([]int, error) {
	out := append([]int(nil), uids...)
	for _, name := range names {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("sockutil: user %q: %w", name, err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, nil
}

// PeerUID reads SO_PEERCRED of a connection.
func PeerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}
