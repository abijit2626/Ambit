//go:build windows

package fsperm

import (
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
