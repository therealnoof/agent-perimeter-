// Package sandbox builds the bubblewrap (bwrap) command line and the seccomp
// filter that confine the worker and every executor. Requirement E-2/E-3,
// week 4.
//
// # What the sandbox is
//
// bwrap is a small setuid-free tool that uses Linux namespaces to start a
// process in a private view of the system. We ask it for:
//
//   - all namespaces unshared: no network interfaces at all (--unshare-net),
//     a private PID space, its own IPC, UTS and user namespace
//   - a read-only root built from /usr and the handful of /etc files a
//     runtime needs; nothing of the host's home directories, keys, or sockets
//     is visible unless listed in Spec
//   - all capabilities dropped, no_new_privs set, parent death kills it
//   - a seccomp filter (see Seccomp) that returns EPERM for syscalls no
//     agent code has a reason to make: mount, ptrace, bpf, keyctl, ...
//
// The one thing the worker needs from outside is fd 3, its end of the
// governor socketpair. bwrap passes inherited fds through untouched, so the
// protocol does not change. An executor needs the secrets and egress proxy
// sockets, which are bound in as files: Unix sockets work across a network
// namespace boundary because they live in the filesystem, not the network
// stack. That is the whole trick of E-4 as redesigned.
//
// This package only builds argument lists and a byte slice; it never runs
// anything (os/exec stays in cmd/agentd/run.go so the import test can keep
// a single eye on it).
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Spec says what one sandboxed process may see.
type Spec struct {
	// Program and Args are the command to run inside.
	Program string
	Args    []string
	// Chdir is the working directory inside the sandbox. It must be one of
	// the ReadOnly paths or a parent of one, or "/" (the default).
	Chdir string
	// ReadOnly paths are bind-mounted read-only at the same absolute path.
	ReadOnly []string
	// Sockets are Unix socket files bound read-write at the same path; the
	// only way a sandboxed process can reach anything outside.
	Sockets []string
	// Tmp mounts a private tmpfs on /tmp (the worker's Python wants one).
	Tmp bool
	// Env is the complete environment inside, as K=V. bwrap starts from an
	// empty one (--clearenv), so nothing of the governor's leaks in.
	Env []string
	// SeccompFD is the fd number (in the child) of a file holding the BPF
	// program from Seccomp(); 0 means no filter.
	SeccompFD int
}

// Available reports whether bwrap is on PATH and returns its location.
// (A hand-rolled lookup: os/exec is kept out of every package but the two
// that spawn, so the import test can watch them.)
func Available() (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "bwrap")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("bubblewrap is not installed (apt install bubblewrap)")
}

// Argv returns the full bwrap command line for spec. The first element is
// the bwrap path; the caller execs it.
func Argv(bwrap string, spec Spec) ([]string, error) {
	if spec.Program == "" {
		return nil, errors.New("sandbox: no program")
	}
	for _, p := range append(append([]string{}, spec.ReadOnly...), spec.Sockets...) {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("sandbox: %q is not absolute", p)
		}
		if strings.Contains(p, "..") {
			return nil, fmt.Errorf("sandbox: %q contains ..", p)
		}
	}

	argv := []string{bwrap,
		"--unshare-all",     // user, ipc, pid, net, uts, cgroup
		"--die-with-parent", // governor dies → sandbox dies
		"--new-session",     // no controlling tty (no TIOCSTI games)
		"--cap-drop", "ALL",
		"--clearenv",
		// A read-only root: the distro's /usr and the merged-usr symlinks.
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/sbin", "/sbin",
		"--proc", "/proc",
		"--dev", "/dev",
	}
	// The few /etc entries a dynamic linker, Python and TLS need. Not /etc
	// itself: no passwd, no hostname, no resolv.conf, no host sockets.
	for _, e := range []string{
		"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
		"/etc/alternatives", "/etc/python3", "/etc/python3.12", "/etc/python3.11",
		"/etc/ssl", "/etc/ca-certificates", "/etc/localtime",
	} {
		argv = append(argv, "--ro-bind-try", e, e)
	}
	if spec.Tmp {
		argv = append(argv, "--tmpfs", "/tmp")
	}
	for _, kv := range spec.Env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("sandbox: env entry %q is not K=V", kv)
		}
		argv = append(argv, "--setenv", k, v)
	}
	for _, p := range spec.ReadOnly {
		argv = append(argv, "--ro-bind", p, p)
	}
	for _, s := range spec.Sockets {
		argv = append(argv, "--bind", s, s)
	}
	if spec.SeccompFD > 0 {
		argv = append(argv, "--seccomp", fmt.Sprint(spec.SeccompFD))
	}
	chdir := spec.Chdir
	if chdir == "" {
		chdir = "/"
	}
	argv = append(argv, "--chdir", chdir, "--", spec.Program)
	argv = append(argv, spec.Args...)
	return argv, nil
}

// SeccompFile writes the BPF program to an unlinked temp file and returns it
// open for reading, ready to hand to the child as an extra fd.
func SeccompFile() (*os.File, error) {
	prog, err := Seccomp()
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "seccomp-*.bpf")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name()) // the open fd is all we need
	if _, err := f.Write(prog); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
