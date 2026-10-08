//go:build windows

package fsperm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func aclOf(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command(icacls(), dir).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v: %s", dir, err, out)
	}
	return string(out)
}

func TestPrivateDirACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	acl := aclOf(t, dir)

	// Inherited entries are what let other local users in; icacls marks them (I).
	if strings.Contains(acl, "(I)") {
		t.Errorf("directory still inherits access from its parent:\n%s", acl)
	}
	for _, broad := range []string{`BUILTIN\Users`, "Everyone", `NT AUTHORITY\Authenticated Users`} {
		if strings.Contains(acl, broad) {
			t.Errorf("%s still has access:\n%s", broad, acl)
		}
	}
	// SYSTEM must keep access: the Wazuh agent reads events.jsonl as SYSTEM.
	if !strings.Contains(acl, `NT AUTHORITY\SYSTEM`) {
		t.Errorf("SYSTEM lost access, so the Wazuh agent could not tail the sink:\n%s", acl)
	}
	if !strings.Contains(acl, `BUILTIN\Administrators`) {
		t.Errorf("Administrators lost access:\n%s", acl)
	}

	// A file created inside inherits the restricted ACL, not the parent's.
	f := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fileACL := aclOf(t, f); strings.Contains(fileACL, `BUILTIN\Users`) {
		t.Errorf("a file in the private directory is readable by Users:\n%s", fileACL)
	}
}

func TestPrivateDirDoesNotTouchAnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	before := aclOf(t, dir)
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if after := aclOf(t, dir); after != before {
		t.Errorf("an existing directory's ACL changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// Parents that PrivateDir creates are restricted too, not just the leaf.
func TestPrivateDirRestrictsCreatedParentsACL(t *testing.T) {
	root := t.TempDir()
	if err := PrivateDir(filepath.Join(root, "outer", "inner")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "outer"), filepath.Join(root, "outer", "inner")} {
		if acl := aclOf(t, d); strings.Contains(acl, "(I)") || strings.Contains(acl, `BUILTIN\Users`) {
			t.Errorf("%s is not private:\n%s", d, acl)
		}
	}
}

// A directory somebody pre-created with the inherited ACL (an installer making
// C:\ProgramData\ambit to drop config.json into) is not private, and ambit must say so
// instead of putting prompt text and the fingerprint key in it.
func TestPrivateDirRefusesAnExposedExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(icacls(), dir, "/grant", "*S-1-5-32-545:(OI)(CI)R").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	err := PrivateDir(dir)
	if !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("err = %v, want ErrNotPrivate for a directory Users can read", err)
	}
	if !strings.Contains(err.Error(), "icacls") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
}

// A directory ambit made itself is accepted on the next run: the check must not
// reject its own output.
func TestPrivateDirAcceptsADirectoryItMadeEarlier(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	for i := 0; i < 2; i++ {
		if err := PrivateDir(dir); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
}
