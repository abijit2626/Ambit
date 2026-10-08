package fsperm

import (
	"errors"
	"strings"
	"testing"
)

const testSelf = "S-1-5-21-1004336348-1177238915-682003330-1001"

// What `icacls /inheritance:r /grant:r` as written in fsperm_windows.go produces.
var privateSDDL = "O:" + testSelf + "D:PAI(A;OICI;FA;;;" + testSelf + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func TestAuditAcceptsAPrivateDirectory(t *testing.T) {
	for name, sddl := range map[string]string{
		"owned by the current user":           privateSDDL,
		"owned by Administrators":             "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"owned by SYSTEM, spelled as a SID":   "O:S-1-5-18D:PAI(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)",
		"deny entry for Users is not a grant": "O:BAD:PAI(D;OICI;FA;;;BU)(A;OICI;FA;;;SY)",
		"group section is skipped":            "O:BAG:SYD:P(A;OICI;FA;;;SY)",
		"SACL is skipped":                     "O:BAD:P(A;OICI;FA;;;BA)S:AI(AU;SA;FA;;;WD)",
	} {
		if err := audit(`C:\ProgramData\ambit`, sddl, testSelf); err != nil {
			t.Errorf("%s: unexpectedly refused: %v", name, err)
		}
	}
}

// The usual way a directory ends up shared is that it was created under
// C:\ProgramData and inherited its parent's entries.
func TestAuditRefusesBroadAccess(t *testing.T) {
	for name, sddl := range map[string]string{
		"Users":               "O:BAD:PAI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)",
		"Users as a SID":      "O:BAD:PAI(A;OICIID;0x1200a9;;;S-1-5-32-545)",
		"Everyone":            "O:BAD:P(A;OICI;FA;;;WD)",
		"Authenticated Users": "O:BAD:PAI(A;OICIID;0x1301bf;;;AU)",
		"Interactive":         "O:BAD:PAI(A;OICI;0x1200a9;;;IU)",
		"Domain Users":        "O:BAD:PAI(A;OICI;0x1200a9;;;S-1-5-21-1-2-3-513)",
		"Domain Users code":   "O:BAD:PAI(A;OICI;0x1200a9;;;DU)",
		"inherit-only entry":  "O:BAD:PAI(A;OICIIO;GR;;;BU)", // applies to what is created inside
		"conditional entry":   "O:BAD:PAI(XA;OICI;FA;;;BU;(@User.Title==\"x\"))",
	} {
		err := audit(`C:\ProgramData\ambit`, sddl, testSelf)
		if !errors.Is(err, ErrNotPrivate) {
			t.Errorf("%s: err = %v, want ErrNotPrivate", name, err)
		}
	}
}

// A null DACL grants everyone full access; it is the absence of an "D:" section.
func TestAuditRefusesNoAccessList(t *testing.T) {
	for _, sddl := range []string{"O:BA", "O:BAD:NO_ACCESS_CONTROL"} {
		if err := audit(`C:\x`, sddl, testSelf); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("%q: err = %v, want ErrNotPrivate", sddl, err)
		}
	}
}

// The owner can rewrite the ACL, so a closed ACL on somebody else's directory is not
// private. This is the squatted C:\ProgramData\ambit.
func TestAuditRefusesAForeignOwner(t *testing.T) {
	sddl := "O:S-1-5-21-1004336348-1177238915-682003330-1999D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	err := audit(`C:\ProgramData\ambit`, sddl, testSelf)
	if !errors.Is(err, ErrNotPrivate) || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("err = %v, want an ErrNotPrivate that says who owns it", err)
	}
	if err := audit(`C:\x`, "D:P(A;OICI;FA;;;SY)", testSelf); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("a descriptor with no owner was accepted: %v", err)
	}
}

func TestAuditNamesTheFix(t *testing.T) {
	err := audit(`C:\ProgramData\ambit`, "O:BAD:PAI(A;OICIID;0x1200a9;;;BU)", testSelf)
	if err == nil || !strings.Contains(err.Error(), "icacls") || !strings.Contains(err.Error(), `C:\ProgramData\ambit`) {
		t.Errorf("the error should say how to fix it: %v", err)
	}
}

func TestParseSDDLRejectsGarbage(t *testing.T) {
	for _, s := range []string{"nonsense", "O:BAD:P(A;OICI;FA;;;SY", "O:BAD:P(A;OICI)", "Z:BA"} {
		if _, err := parseSDDL(s); err == nil {
			t.Errorf("parseSDDL(%q) = nil error, want one", s)
		}
	}
}
