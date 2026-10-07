package fsperm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateDirCreatesNestedDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	// The directory has to stay usable by its owner after it is locked down.
	f := filepath.Join(dir, "x")
	if err := os.WriteFile(f, []byte("ok"), 0o600); err != nil {
		t.Fatalf("owner cannot write into the private directory: %v", err)
	}
	if _, err := os.ReadFile(f); err != nil {
		t.Fatalf("owner cannot read back from the private directory: %v", err)
	}
}

func TestPrivateDirUnixMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not access control on Windows; fsperm_windows_test.go checks the ACL")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o, want 700", perm)
	}
}

// An existing directory belongs to whoever made it. Locking down C:\ProgramData
// because an operator pointed events_path at it would break every other program.
func TestPrivateDirLeavesExistingDirectoryAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by the Windows ACL test")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o755 {
		t.Errorf("existing directory mode changed to %o, want it left at 755", perm)
	}
}
