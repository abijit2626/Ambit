package fsperm

import (
	"fmt"
	"strings"
)

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

var sidAliases = map[string]string{
	"SY": sidSystem,
	"BA": sidAdministrators,
	"WD": "S-1-1-0",
	"BU": "S-1-5-32-545",
	"BG": "S-1-5-32-546",
	"AN": "S-1-5-7",
	"IU": "S-1-5-4",
	"NU": "S-1-5-2",
	"AU": "S-1-5-11",
}

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

func isDomainBroad(s string) bool {
	switch strings.ToUpper(s) {
	case "DU", "DG":
		return true
	}
	return strings.HasPrefix(s, "S-1-5-21-") && (strings.HasSuffix(s, "-513") || strings.HasSuffix(s, "-514"))
}

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

func audit(dir, sddl, self string) error {
	d, err := parseSDDL(sddl)
	if err != nil {
		return fmt.Errorf("fsperm: %s: %w", dir, err)
	}
	fix := fmt.Sprintf("restrict it with: icacls \"%s\" /inheritance:r /grant:r *%s:(OI)(CI)F *%s:(OI)(CI)F *%s:(OI)(CI)F, or remove it so ambit can create it",
		dir, self, sidSystem, sidAdministrators)

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
