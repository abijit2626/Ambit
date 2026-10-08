//go:build windows

package fsperm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// The SIDs are the same on every Windows machine and in every locale, unlike the names
// "SYSTEM" and "Administrators"; sidSystem and sidAdministrators are in sddl.go.

// restrict replaces dir's ACL with full control for the current user, SYSTEM and
// Administrators, inherited by everything created inside, and removes every
// inherited entry — which is what grants BUILTIN\Users read access under
// C:\ProgramData.
//
// It shells out to icacls rather than calling SetNamedSecurityInfo because ambitd has
// no third-party dependencies by design, and the standard library's syscall package
// does not expose ACL editing. icacls is invoked by absolute path under SystemRoot so
// a hostile PATH cannot substitute it: this binary runs on the same endpoint the
// threat model says may already be compromised.
func restrict(dir string) error {
	user, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("fsperm: current user: %w", err)
	}
	args := []string{dir, "/inheritance:r"}
	for _, sid := range []string{user, sidSystem, sidAdministrators} {
		args = append(args, "/grant:r", "*"+sid+":(OI)(CI)F")
	}
	out, err := exec.Command(icacls(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fsperm: icacls %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func icacls() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "icacls.exe")
}

func currentUserSID() (string, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecurityInfo = advapi32.NewProc("GetNamedSecurityInfoW")
	procConvertSDToString    = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
)

const (
	seFileObject             = 1
	ownerSecurityInformation = 0x1
	daclSecurityInformation  = 0x4
	sddlRevision1            = 1
)

// checkExisting refuses a directory that was not made private. It reads the owner and
// the access list in SDDL form and applies audit to them. A directory whose descriptor
// cannot be read is refused too: if ambit cannot tell that it is private, it is not
// going to put prompt text in it.
func checkExisting(dir string) error {
	sddl, err := securityDescriptor(dir)
	if err != nil {
		return fmt.Errorf("fsperm: cannot read the access list of the existing directory %s, so cannot tell that it is private: %w", dir, err)
	}
	self, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("fsperm: current user: %w", err)
	}
	return audit(dir, sddl, self)
}

// securityDescriptor returns the owner and DACL of a file or directory as SDDL.
func securityDescriptor(path string) (string, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var sd uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(name)), seFileObject, ownerSecurityInformation|daclSecurityInformation,
		0, 0, 0, 0, uintptr(unsafe.Pointer(&sd)),
	); r != 0 {
		return "", fmt.Errorf("GetNamedSecurityInfo: %w", syscall.Errno(r))
	}
	defer syscall.LocalFree(syscall.Handle(sd))

	var str *uint16
	if r, _, e := procConvertSDToString.Call(
		sd, sddlRevision1, ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&str)), 0,
	); r == 0 {
		return "", fmt.Errorf("ConvertSecurityDescriptorToStringSecurityDescriptor: %w", e)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(str))))

	n := 0
	for p := unsafe.Pointer(str); *(*uint16)(p) != 0; p = unsafe.Add(p, 2) {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(str, n)), nil
}
