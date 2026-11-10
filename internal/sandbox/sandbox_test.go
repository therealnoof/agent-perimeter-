package sandbox

import (
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestArgv(t *testing.T) {
	argv, err := Argv("/usr/bin/bwrap", Spec{
		Program:   "/usr/bin/python3",
		Args:      []string{"agents/stub_worker.py"},
		Chdir:     "/srv/ap",
		ReadOnly:  []string{"/srv/ap/agents", "/srv/ap/client"},
		Sockets:   []string{"/srv/ap/run/egress.sock"},
		Tmp:       true,
		Env:       []string{"PATH=/usr/bin", "PERIMETER_FD=3"},
		SeccompFD: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(argv, " ")
	for _, want := range []string{
		"--unshare-all", "--cap-drop ALL", "--die-with-parent", "--clearenv",
		"--ro-bind /usr /usr", "--ro-bind /srv/ap/agents /srv/ap/agents",
		"--bind /srv/ap/run/egress.sock /srv/ap/run/egress.sock",
		"--tmpfs /tmp", "--setenv PATH /usr/bin", "--setenv PERIMETER_FD 3", "--seccomp 4", "--chdir /srv/ap -- /usr/bin/python3 agents/stub_worker.py",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// /etc as a whole must never be bound.
	if strings.Contains(s, "--ro-bind /etc /etc") || strings.Contains(s, "--bind /etc ") {
		t.Error("whole /etc bound")
	}
	if _, err := Argv("bwrap", Spec{Program: "x", ReadOnly: []string{"relative"}}); err == nil {
		t.Error("relative path accepted")
	}
	if _, err := Argv("bwrap", Spec{Program: "x", ReadOnly: []string{"/a/../b"}}); err == nil {
		t.Error("dotdot path accepted")
	}
}

// The program must decode as valid sock_filter instructions with every
// jump landing inside the program.
func TestSeccompStructure(t *testing.T) {
	prog, err := Seccomp()
	if err != nil {
		t.Skip(err)
	}
	if len(prog)%8 != 0 {
		t.Fatal("not a whole number of instructions")
	}
	n := len(prog) / 8
	for i := 0; i < n; i++ {
		code := binary.LittleEndian.Uint16(prog[i*8:])
		jt, jf := int(prog[i*8+2]), int(prog[i*8+3])
		if code == 0x15 { // jeq: targets are pc+1+jt / pc+1+jf
			if i+1+jt >= n || i+1+jf >= n {
				t.Fatalf("insn %d jumps out of program", i)
			}
		}
	}
	last := binary.LittleEndian.Uint16(prog[(n-1)*8:])
	if last != 0x06 {
		t.Fatal("program does not end in a return")
	}
}

// Install the filter in a child process and check it does what it says:
// a denied syscall fails with EPERM, an ordinary one still works, and the
// process is not killed. This is the real test; the structure test above
// is only a sanity check.
func TestSeccompEnforces(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Getenv("SANDBOX_SECCOMP_CHILD") == "1" {
		childApplyAndProbe()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompEnforces")
	cmd.Env = append(os.Environ(), "SANDBOX_SECCOMP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "denied=EPERM allowed=ok") {
		t.Fatalf("unexpected child output:\n%s", out)
	}
}

func childApplyAndProbe() {
	prog, err := Seccomp()
	if err != nil {
		println("seccomp:", err.Error())
		os.Exit(1)
	}
	const (
		prSetNoNewPrivs = 38
		prSetSeccomp    = 22
		seccompModeFilt = 2
	)
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		println("no_new_privs:", e.Error())
		os.Exit(1)
	}
	type sockFprog struct {
		len    uint16
		_      [6]byte
		filter *byte
	}
	fp := sockFprog{len: uint16(len(prog) / 8), filter: &prog[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilt, uintptr(unsafe.Pointer(&fp))); e != 0 {
		println("seccomp install:", e.Error())
		os.Exit(1)
	}
	// unshare(CLONE_NEWUTS) is on the deny list on both architectures.
	denied := "?"
	if err := syscall.Unshare(syscall.CLONE_NEWUTS); err == syscall.EPERM {
		denied = "EPERM"
	} else if err != nil {
		denied = err.Error()
	} else {
		denied = "ALLOWED"
	}
	allowed := "?"
	if _, err := os.Getwd(); err == nil {
		allowed = "ok"
	}
	println("denied=" + denied + " allowed=" + allowed)
	os.Exit(0)
}
