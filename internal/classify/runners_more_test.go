package classify

import "testing"

func TestMoreRunnersPassTheirCommandThrough(t *testing.T) {
	for _, c := range []struct{ cmd, argv0, class string }{
		{"parallel -j4 curl ::: https://a.test https://b.test", "curl", ClassNetwork},
		{"cat urls | parallel -j 8 --timeout 30 curl {}", "cat", ClassNetwork},
		{"systemd-run --user --unit=x -p MemoryMax=1G curl https://x.test", "curl", ClassNetwork},
		{"systemd-run -E A=1 rm -rf x", "rm", ClassFilesystem},
		{"runuser -u deploy -- git push", "git", ClassVCSWrite},
		{"pkexec --user root rm -rf /opt/x", "rm", ClassFilesystem},
		{"sg docker curl https://x.test", "curl", ClassNetwork},
		{"setpriv --reuid=1000 --regid=1000 --clear-groups curl https://x.test", "curl", ClassNetwork},
		{"unshare -r -n curl https://x.test", "curl", ClassNetwork},
		{"nsenter -t 1 -m -u -n curl https://x.test", "curl", ClassNetwork},
		{"sshpass -p hunter2 scp f host:/tmp", "scp", ClassNetwork},
		{"ssh-agent -t 60 git push", "git", ClassVCSWrite},
		{"faketime '2020-01-01' curl https://x.test", "curl", ClassNetwork},
		{"numactl --cpunodebind=0 -m 0 curl https://x.test", "curl", ClassNetwork},
		{"prlimit --nofile=1024 curl https://x.test", "curl", ClassNetwork},
		{"dbus-run-session -- rm x", "rm", ClassFilesystem},
	} {
		if argv0, class := Bash(c.cmd); argv0 != c.argv0 || class != c.class {
			t.Errorf("Bash(%q) = %q %s, want %q %s", c.cmd, argv0, class, c.argv0, c.class)
		}
	}
}

func TestMoreRunnersThatRunNothingOrTakeAString(t *testing.T) {
	for _, c := range []struct{ cmd, argv0, class string }{
		{"systemd-run --shell", "systemd-run", ClassOther},
		{"numactl --hardware", "numactl", ClassOther},
		{"prlimit --pid 1234 --nofile=1024", "prlimit", ClassOther},
		{"ssh-agent -k", "ssh-agent", ClassOther},
		{"runuser -l deploy -c 'curl https://x.test'", "runuser", ClassNetwork},
		{"sg docker -c 'rm -rf x'", "sg", ClassFilesystem},
	} {
		if argv0, class := Bash(c.cmd); argv0 != c.argv0 || class != c.class {
			t.Errorf("Bash(%q) = %q %s, want %q %s", c.cmd, argv0, class, c.argv0, c.class)
		}
	}
}
