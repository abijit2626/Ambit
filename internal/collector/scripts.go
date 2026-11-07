package collector

import (
	"path"
	"slices"
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
// The destinations a network script names and the credential paths it reads are kept the same way,
// as keyed digests, and come with it when it runs: D9 reports the destinations, with egress_source
// "script", and the paths reach bit B, the gate, D1 and D2 as a Read of them would.
//
// A script is recorded from Write's content, Edit's and MultiEdit's new text (raising the class it
// had, since an edit adds to a file ambitd may not have seen whole), and a Bash here-document written
// to a file. classify.ScriptClass decides what is a script, by shebang or extension.

// maxSessionScripts bounds how many scripts a session remembers. The oldest is forgotten first, so
// writing many scripts cannot push out the one written last before it runs.
const maxSessionScripts = 256

// maxScriptDestinations and maxScriptPaths bound what one script contributes when it runs.
const (
	maxScriptDestinations = 32
	maxScriptPaths        = 16
)

// scriptFacts is what ambitd keeps about a script the session wrote, all of it derived when the
// script was written: its class, the keyed digests of the destinations it names when it is a network
// script, and the credential paths it names, as digests with their zone. Never the content.
type scriptFacts struct {
	class string
	dests []string
	paths []event.PathRef
}

func (f scriptFacts) merge(g scriptFacts) scriptFacts {
	f.class = classify.Max(f.class, g.class)
	for _, d := range g.dests {
		if len(f.dests) < maxScriptDestinations && !slices.Contains(f.dests, d) {
			f.dests = append(f.dests, d)
		}
	}
	for _, p := range g.paths {
		if len(f.paths) < maxScriptPaths && !slices.Contains(f.paths, p) {
			f.paths = append(f.paths, p)
		}
	}
	return f
}

type sessionScripts struct {
	facts map[string]scriptFacts
	order []string
}

func (s *sessionScripts) remember(key string, f scriptFacts, raise bool) {
	if s.facts == nil {
		s.facts = map[string]scriptFacts{}
	}
	if old, ok := s.facts[key]; ok {
		if raise {
			f = old.merge(f)
		}
		s.facts[key] = f
		return
	}
	if len(s.order) >= maxSessionScripts {
		delete(s.facts, s.order[0])
		s.order = s.order[1:]
	}
	s.facts[key] = f
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

// factsOf derives what is kept about a script from its content, or false when it is not a script.
func (c *Collector) factsOf(st *sessionState, file, content string) (scriptFacts, bool) {
	class, ok := classify.ScriptClass(file, content)
	if !ok {
		return scriptFacts{}, false
	}
	f := scriptFacts{class: class}
	if classify.IsNetworkClass(class) {
		// Redacted first, as a command's text is: a secret in the script is not a destination.
		clean, _ := c.red.Redact(content)
		f.dests = c.ext.Destinations(clean)
		if len(f.dests) > maxScriptDestinations {
			f.dests = f.dests[:maxScriptDestinations]
		}
	}
	for _, u := range classify.ScriptCredentialPaths(file, content) {
		if len(f.paths) == maxScriptPaths {
			break
		}
		f.paths = append(f.paths, event.PathRef{PathDigest: c.ext.Digest(u.Path), Zone: st.zone(u.Path), Op: "read"})
	}
	return f, true
}

// recordScripts remembers the scripts a tool call writes.
func (c *Collector) recordScripts(st *sessionState, p *hook.Payload) {
	if p.HookEventName != hook.EvPreToolUse {
		return
	}
	type written struct {
		file, content string
		raise         bool
	}
	var ws []written
	file := p.StringField("file_path")
	switch p.ToolName {
	case "Write":
		ws = append(ws, written{file, p.StringField("content"), false})
	case "Edit":
		ws = append(ws, written{file, p.StringField("new_string"), true})
	case "MultiEdit":
		if edits, ok := p.ToolInput["edits"].([]any); ok {
			for _, e := range edits {
				if m, ok := e.(map[string]any); ok {
					if s, ok := m["new_string"].(string); ok {
						ws = append(ws, written{file, s, true})
					}
				}
			}
		}
	}
	if cmd := p.Command(); cmd != "" {
		for _, w := range classify.FilesWritten(cmd) {
			ws = append(ws, written{w.Path, w.Content, false})
		}
	}
	if len(ws) == 0 {
		return
	}
	// The facts are derived before the session is locked: st.zone takes the lock itself.
	type fact struct {
		file  string
		f     scriptFacts
		raise bool
	}
	var fs []fact
	for _, w := range ws {
		if f, ok := c.factsOf(st, w.file, w.content); ok {
			fs = append(fs, fact{w.file, f, w.raise})
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	cwd := p.CWD
	if cwd == "" {
		cwd = st.cwd
	}
	for _, f := range fs {
		if key := scriptKey(f.file, cwd, st.home); key != "" {
			st.scripts.remember(key, f.f, f.raise)
		}
	}
}

// runScripts is what the scripts a command runs, that the session wrote, add up to.
func (c *Collector) runScripts(st *sessionState, p *hook.Payload, cmd string) (scriptFacts, bool) {
	runs := classify.ScriptsRun(cmd)
	if len(runs) == 0 {
		return scriptFacts{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	cwd := p.CWD
	if cwd == "" {
		cwd = st.cwd
	}
	var all scriptFacts
	found := false
	for _, r := range runs {
		if f, ok := st.scripts.facts[scriptKey(r.Path, cwd, st.home)]; ok {
			all, found = all.merge(f), true
		}
	}
	return all, found
}

// applyScripts gives a Bash command what the scripts it runs do: at least their class, and the
// credential paths they read, recorded as a Read of them would be.
func (c *Collector) applyScripts(st *sessionState, p *hook.Payload, t *event.Tool, cmd string) {
	f, ok := c.runScripts(st, p, cmd)
	if !ok {
		return
	}
	t.Bash.CommandClass = classify.Max(t.Bash.CommandClass, f.class)
	for _, ref := range f.paths {
		if !slices.Contains(t.Paths, ref) {
			t.Paths = append(t.Paths, ref)
		}
	}
}
