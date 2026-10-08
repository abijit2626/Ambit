package fsperm

import (
	"errors"
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

func TestPrivateDirUnixModeOfCreatedParents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not access control on Windows")
	}
	root := t.TempDir()
	if err := PrivateDir(filepath.Join(root, "a", "b")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("created parent mode = %o, want 700", perm)
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

// A failed restriction must not leave the directory behind. It would have the inherited
// ACL, and the next run, finding it already there, would take it for somebody else's and
// use it as it is.
func TestPrivateDirRemovesWhatItCreatedWhenRestrictingFails(t *testing.T) {
	old := restrictDir
	defer func() { restrictDir = old }()
	boom := errors.New("icacls: access denied")
	restrictDir = func(string) error { return boom }

	root := t.TempDir()
	dir := filepath.Join(root, "a", "b", "c")
	if err := PrivateDir(dir); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the restriction error", err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		t.Errorf("directories created before the failure were left behind: %v", err)
	}

	restrictDir = old
	if err := PrivateDir(dir); err != nil {
		t.Fatalf("a retry after the failure should succeed: %v", err)
	}
}

// Every directory created along the way is restricted, not just the last one. A parent
// created with the inherited ACL stays that way, because a later run finds it existing.
func TestPrivateDirRestrictsEveryDirectoryItCreates(t *testing.T) {
	old := restrictDir
	defer func() { restrictDir = old }()
	var got []string
	restrictDir = func(d string) error { got = append(got, d); return nil }

	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "a"), dir}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("restricted %v, want %v (outermost first, and not the pre-existing root)", got, want)
	}

	// A directory that was already there is not restricted again.
	got = nil
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("an existing directory was restricted: %v", got)
	}
}

func TestPrivateDirRefusesAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(f); err == nil {
		t.Error("a regular file was accepted as a directory")
	}
	if err := PrivateDir(filepath.Join(f, "sub")); err == nil {
		t.Error("a directory below a regular file was accepted")
	}
}
