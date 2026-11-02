package classify

import "strings"

// windowsInner is the command a Windows tool runs on the caller's behalf, as innerCommand reads
// "bash -c" or "cmd /c":
//
//   - runas /user:NAME "program args": the first word that is not one of its /options
//   - schtasks /create ... /tr "program args": the task's command, which runs later, as a task
//   - wmic process call create "program args": a new process, here or on /node:
//   - forfiles ... /c "command": run once per matching file
//
// Options are matched without regard to case, as Windows does.
func windowsInner(tool string, args []string) (string, bool) {
	switch tool {
	case "runas":
		for i, a := range args {
			if !strings.HasPrefix(stripQuotes(a), "/") {
				return joinArgs(args[i:]), true
			}
		}
	case "schtasks":
		return slashValue(args, "/tr")
	case "forfiles":
		return slashValue(args, "/c")
	case "wmic":
		for i := 0; i+2 < len(args); i++ {
			if strings.EqualFold(stripQuotes(args[i]), "call") && strings.EqualFold(stripQuotes(args[i+1]), "create") {
				return joinArgs(args[i+2:]), true
			}
		}
	}
	return "", false
}

// slashValue is the word after the option name, matched without regard to case, as in
// "schtasks /create /tr cmd" or "forfiles /c cmd".
func slashValue(args []string, name string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if strings.EqualFold(stripQuotes(args[i]), name) {
			return stripQuotes(args[i+1]), true
		}
	}
	return "", false
}
