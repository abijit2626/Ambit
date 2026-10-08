package fsperm

import (
	"fmt"
	"strings"
)

// This file reads the Security Descriptor Definition Language form of an access
// list. It has no build constraint, although only Windows produces such strings, so
// that the logic that decides whether a directory is private can be tested anywhere.
//
// SDDL is used rather than the output of `icacls dir` because icacls prints account
// names, which are localized ("BUILTIN\Users" is "VORDEFINIERT\Benutzer" on a German
// system) and would make the check fail open on every non-English endpoint. SDDL
// carries SIDs and two-letter codes that are the same everywhere.

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// sidAliases expands the two-letter SDDL codes this file cares about.
var sidAliases = map[string]string{
	"SY": sidSystem,
	"BA": sidAdministrators,
	"WD": "S-1-1-0",      // Everyone
	"BU": "S-1-5-32-545", // Users
	"BG": "S-1-5-32-546", // Guests
	"AN": "S-1-5-7",      // Anonymous
	"IU": "S-1-5-4",      // Interactive
	"NU": "S-1-5-2",      // Network
	"AU": "S-1-5-11",     // Authenticated Users
}

// broadSIDs are accounts that stand for far more than one person. An allow entry
// for any of them on a directory means other local accounts can read what is in it.
var broadSIDs = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-7":      "Anonymous",
	"S-1-5-4":      "Interactive",
	"S-1-5-2":      "Network",
	"S-1-5-11":     "Authenticated Users",
}

type ace struct {
	typ, flags, rights, sid string
}

type descriptor struct {
	owner   string
	hasDACL bool
	aces    []ace
}

func canonicalSID(s string) string {
	if full, ok := sidAliases[strings.ToUpper(s)]; ok {
		return full
	}
	return strings.ToUpper(s)
}

// isDomainBroad reports Domain Users and Domain Guests, whose SIDs carry the domain's
// identifier and so cannot be listed in advance. DU and DG are their SDDL codes.
func isDomainBroad(s string) bool {
	switch strings.ToUpper(s) {
	case "DU", "DG":
		return true
	}
	return strings.HasPrefix(s, "S-1-5-21-") && (strings.HasSuffix(s, "-513") || strings.HasSuffix(s, "-514"))
}

// parseSDDL reads the owner and the DACL out of an SDDL string such as
// "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)". The group and the SACL are skipped.
func parseSDDL(s string) (descriptor, error) {
	var d descriptor
	i := 0
	for i < len(s) {
		if i+1 >= len(s) || s[i+1] != ':' {
			return d, fmt.Errorf("malformed security descriptor %q at offset %d", s, i)
		}
		tag := s[i]
		i += 2
		switch tag {
		case 'O', 'G':
			n := sidLen(s[i:])
			if n == 0 {
				return d, fmt.Errorf("malformed security descriptor %q: empty SID", s)
			}
			if tag == 'O' {
				d.owner = s[i : i+n]
			}
			i += n
		case 'D', 'S':
			// Flags (P, AR, AI, NO_ACCESS_CONTROL) run up to the first ACE or the next
			// section.
			start := i
			for i < len(s) && s[i] != '(' && !(i+1 < len(s) && s[i+1] == ':' && strings.IndexByte("OGDS", s[i]) >= 0) {
				i++
			}
			if tag == 'D' {
				d.hasDACL = !strings.Contains(s[start:i], "NO_ACCESS_CONTROL")
			}
			for i < len(s) && s[i] == '(' {
				end := matchParen(s, i)
				if end < 0 {
					return d, fmt.Errorf("malformed security descriptor %q: unbalanced parenthesis", s)
				}
				if tag == 'D' {
					f := strings.SplitN(s[i+1:end], ";", 7)
					if len(f) < 6 {
						return d, fmt.Errorf("malformed ACE %q", s[i:end+1])
					}
					d.aces = append(d.aces, ace{typ: f[0], flags: f[1], rights: f[2], sid: f[5]})
				}
				i = end + 1
			}
		default:
			return d, fmt.Errorf("malformed security descriptor %q: unknown section %q", s, string(tag))
		}
	}
	return d, nil
}

// sidLen is the length of the SID at the start of s: a full S-1-... string, or a
// two-letter code.
func sidLen(s string) int {
	if len(s) >= 2 && (s[0] == 'S' || s[0] == 's') && s[1] == '-' {
		n := 2
		for n < len(s) && (s[n] == '-' || (s[n] >= '0' && s[n] <= '9')) {
			n++
		}
		return n
	}
	if len(s) >= 2 {
		return 2
	}
	return 0
}

// matchParen returns the index of the parenthesis closing the one at s[open]. Nested
// pairs occur in conditional ACEs.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// audit decides whether a directory whose descriptor is sddl is private to self (the
// current account's SID), SYSTEM and Administrators. It returns nil, or an error
// wrapping ErrNotPrivate that says what is wrong and how to fix it.
func audit(dir, sddl, self string) error {
	d, err := parseSDDL(sddl)
	if err != nil {
		return fmt.Errorf("fsperm: %s: %w", dir, err)
	}
	fix := fmt.Sprintf("restrict it with: icacls \"%s\" /inheritance:r /grant:r *%s:(OI)(CI)F *%s:(OI)(CI)F *%s:(OI)(CI)F, or remove it so ambit can create it",
		dir, self, sidSystem, sidAdministrators)

	// The owner can always rewrite the ACL, whatever it says, so a directory owned by
	// some other account is not private even if its ACL looks closed. This is the
	// shape of a squatted C:\ProgramData\ambit: ProgramData lets any user create
	// subfolders, and whoever gets there first owns the result.
	owner := canonicalSID(d.owner)
	if owner == "" || (owner != canonicalSID(self) && owner != sidSystem && owner != sidAdministrators) {
		return fmt.Errorf("fsperm: %s: %w: it is owned by %q, not by this account, SYSTEM or Administrators, and its owner can change who may read it; %s",
			dir, ErrNotPrivate, d.owner, fix)
	}
	if !d.hasDACL {
		return fmt.Errorf("fsperm: %s: %w: it has no access list, which grants everyone full access; %s", dir, ErrNotPrivate, fix)
	}
	for _, a := range d.aces {
		switch a.typ {
		case "A", "XA", "OA":
		default:
			continue
		}
		sid := canonicalSID(a.sid)
		who, broad := broadSIDs[sid]
		if !broad && isDomainBroad(a.sid) {
			who, broad = a.sid, true
		}
		if broad {
			return fmt.Errorf("fsperm: %s: %w: %s has access to it, so the prompt text, events and key ambit puts there would be readable by other accounts; %s",
				dir, ErrNotPrivate, who, fix)
		}
	}
	return nil
}
