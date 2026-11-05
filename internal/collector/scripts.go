package collector

import (
	"path"
	"strings"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
)

// An agent often writes a script and runs it in a later step: Write upload.py, then
// "python3 upload.py". The command names only the file, so the classifier cannot see what running it
// does. ambitd saw the content when it was written, though, so each session remembers the class of
// the scripts it wrote, by path, and a command that runs one is classed at least as that script is.
// Only the class is kept, never the content.
//
// A script is recorded from Write's content, Edit's and MultiEdit's new text (raising the class it
// had, since an edit adds to a file ambitd may not have seen whole), and a Bash here-document written
// to a file. classify.ScriptClass decides what is a script, by shebang or extension.

// maxSessionScripts bounds how many scripts a session remembers. The oldest is forgotten first, so
// writing many scripts cannot push out the one written last before it runs.
const maxSessionScripts = 256

type sessionScripts struct {
	class map[string]string
	order []string
}

func (s *sessionScripts) remember(key, class string, raise bool) {
	if s.class == nil {
		s.class = map[string]string{}
	}
	if old, ok := s.class[key]; ok {
		if raise {
			class = classify.Max(old, class)
		}
		s.class[key] = class
		return
	}
	if len(s.order) >= maxSessionScripts {
		delete(s.class, s.order[0])
		s.order = s.order[1:]
	}
	s.class[key] = class
	s.order = append(s.order, key)
}

// scriptKey is the path a script is remembered by: cleaned, with "/" separators, and resolved against
// the session's directory when relative, so "x.py" run from the directory it was written in and
// "/home/dev/repo/x.py" are the same script.
func scriptKey(p, cwd, home string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return ""
		}
		p = home + p[1:]
	case !strings.HasPrefix(p, "/") && !(len(p) >= 2 && p[1] == ':'):
		if cwd == "" {
			return ""
		}
		p = strings.ReplaceAll(cwd, `\`, "/") + "/" + p
	}
	return path.Clean(p)
}

// recordScripts remembers the scripts a tool call writes.
func (c *Collector) recordScripts(st *sessionState, p *hook.Payload) {
	if p.HookEventName != hook.EvPreToolUse {
		return
	}
	cwd := p.CWD
	st.mu.Lock()
	defer st.mu.Unlock()
	if cwd == "" {
		cwd = st.cwd
	}
	note := func(file, content string, raise bool) {
		if class, ok := classify.ScriptClass(file, content); ok {
			if key := scriptKey(file, cwd, st.home); key != "" {
				st.scripts.remember(key, class, raise)
			}
		}
	}
	file := p.StringField("file_path")
	switch p.ToolName {
	case "Write":
		note(file, p.StringField("content"), false)
	case "Edit":
		note(file, p.StringField("new_string"), true)
	case "MultiEdit":
		if edits, ok := p.ToolInput["edits"].([]any); ok {
			for _, e := range edits {
				if m, ok := e.(map[string]any); ok {
					if s, ok := m["new_string"].(string); ok {
						note(file, s, true)
					}
				}
			}
		}
	}
	if cmd := p.Command(); cmd != "" {
		for _, w := range classify.FilesWritten(cmd) {
			note(w.Path, w.Content, false)
		}
	}
}

// scriptClassFor raises a Bash command's class to that of any script it runs that the session wrote.
func (c *Collector) scriptClassFor(st *sessionState, p *hook.Payload, b *event.Bash, cmd string) {
	runs := classify.ScriptsRun(cmd)
	if len(runs) == 0 {
		return
	}
	cwd := p.CWD
	st.mu.Lock()
	defer st.mu.Unlock()
	if cwd == "" {
		cwd = st.cwd
	}
	for _, r := range runs {
		if class, ok := st.scripts.class[scriptKey(r.Path, cwd, st.home)]; ok {
			b.CommandClass = classify.Max(b.CommandClass, class)
		}
	}
}
