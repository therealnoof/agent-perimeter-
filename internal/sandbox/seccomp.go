package sandbox

import (
	"encoding/binary"
	"fmt"
	"runtime"
)

// Seccomp returns a classic-BPF program for the running architecture that
// the kernel evaluates on every syscall of the sandboxed process:
//
//	if the syscall's architecture is not ours      → kill the process
//	if the syscall number is on the deny list      → fail it with EPERM
//	otherwise                                      → allow
//
// A deny list, not an allow list, on purpose. An allow list for "whatever
// Python and a Go binary might do" is hundreds of entries that drift with
// every runtime release, and a wrong entry is a silent crash in production.
// The deny list is the short set of syscalls that only matter to someone
// trying to escape: change mounts, trace another process, load kernel
// code, create namespaces, read another process's memory. Together with
// cap-drop ALL and no_new_privs most of these would fail anyway; the filter
// makes that failure independent of how the host is configured.
//
// The encoding is the kernel's struct sock_filter: u16 code, u8 jt, u8 jf,
// u32 k, little-endian, 8 bytes each. No library needed.
func Seccomp() ([]byte, error) {
	tbl, ok := denyTable[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("sandbox: no seccomp table for %s", runtime.GOARCH)
	}
	arch, nrs := tbl.arch, tbl.nrs

	const (
		ldAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
		jeqK  = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
		retK  = 0x06 // BPF_RET | BPF_K

		offNr   = 0 // seccomp_data.nr
		offArch = 4 // seccomp_data.arch

		retAllow = 0x7fff0000
		retKill  = 0x80000000 // SECCOMP_RET_KILL_PROCESS
		retErrno = 0x00050000 // SECCOMP_RET_ERRNO | errno
		eperm    = 1
	)

	type insn struct {
		code uint16
		jt   uint8
		jf   uint8
		k    uint32
	}
	var prog []insn
	// arch check
	prog = append(prog,
		insn{ldAbs, 0, 0, offArch},
		insn{jeqK, 1, 0, arch}, // match → skip the kill
		insn{retK, 0, 0, retKill},
		insn{ldAbs, 0, 0, offNr},
	)
	// one jeq per denied syscall; jt jumps to the shared EPERM return at the
	// end, which is (remaining jeqs + the allow) instructions away
	for i, nr := range nrs {
		remaining := len(nrs) - i - 1
		prog = append(prog, insn{jeqK, uint8(remaining + 1), 0, nr})
	}
	prog = append(prog,
		insn{retK, 0, 0, retAllow},
		insn{retK, 0, 0, retErrno | eperm},
	)
	if len(prog) > 4096 {
		return nil, fmt.Errorf("sandbox: seccomp program too long")
	}

	out := make([]byte, 0, len(prog)*8)
	for _, in := range prog {
		var b [8]byte
		binary.LittleEndian.PutUint16(b[0:], in.code)
		b[2], b[3] = in.jt, in.jf
		binary.LittleEndian.PutUint32(b[4:], in.k)
		out = append(out, b[:]...)
	}
	return out, nil
}

// denyTable: AUDIT_ARCH value and syscall numbers per Go architecture.
// Numbers are from the kernel's syscall tables (x86_64: syscall_64.tbl;
// arm64: the generic unistd.h). Grouped by what they would let a process do.
var denyTable = map[string]struct {
	arch uint32
	nrs  []uint32
}{
	"amd64": {0xc000003e, []uint32{
		// change the filesystem view
		165, 166, 155, 428, 429, 430, 431, 432, 433, 442, // mount umount2 pivot_root open_tree move_mount fsopen fsconfig fsmount fspick mount_setattr
		// observe or alter other processes
		101, 310, 311, 312, 438, // ptrace process_vm_readv process_vm_writev kcmp pidfd_getfd
		// new namespaces (clone flags cannot be filtered; unshare/setns can)
		272, 308, // unshare setns
		// kernel code, kernel keys, performance counters, io_uring
		175, 313, 176, 246, 320, 321, 298, 248, 249, 250, 425, 426, 427, 323, // init_module finit_module delete_module kexec_load kexec_file_load bpf perf_event_open add_key request_key keyctl io_uring_setup io_uring_enter io_uring_register userfaultfd
		// machine state
		169, 167, 168, 163, 164, 227, 159, 170, 171, 172, 173, 135, 133, 259, 134, 153, 304, 279, 256, 179, 180, 212, // reboot swapon swapoff acct settimeofday clock_settime adjtimex sethostname setdomainname iopl ioperm personality mknod mknodat uselib vhangup open_by_handle_at move_pages migrate_pages quotactl nfsservctl lookup_dcookie
	}},
	"arm64": {0xc00000b7, []uint32{
		40, 39, 41, 428, 429, 430, 431, 432, 433, 442,
		117, 270, 271, 272, 438,
		97, 268,
		105, 273, 106, 104, 294, 280, 241, 217, 218, 219, 425, 426, 427, 282,
		142, 224, 225, 89, 170, 112, 171, 161, 162, 92, 33, 58, 265, 239, 238, 60, 42, 18,
	}},
}
