package collector

import (
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/interpose"
)

// maxAnnotatedTools bounds the annotation cache, so a server that lists an unbounded number of tools
// cannot grow ambitd's memory without limit. Tools past the bound are not enriched.
const maxAnnotatedTools = 4096

// annotationCache holds the annotations each MCP server last declared for its tools, as mcp-interpose
// reported them from tools/list, so a tool call from the hook path can carry them. A hook payload has
// none of its own. The interposer's -server name must be the server's key in the MCP configuration,
// which is also the <server> in mcp__<server>__<tool>, or the two never join.
//
// The hints are the server's own claims. They only ever add scrutiny (a destructive or open-world tool
// crosses and alerts); nothing reads a hint to trust a call less, because a hostile server can claim
// anything.
type annotationCache struct {
	byTool map[string]event.Annotations
}

func annotationKey(server, tool string) string { return server + "\x00" + tool }

func (c *Collector) rememberAnnotations(rep *interpose.Report) {
	c.annMu.Lock()
	defer c.annMu.Unlock()
	if c.ann.byTool == nil {
		c.ann.byTool = map[string]event.Annotations{}
	}
	for _, t := range rep.Tools {
		if t.Tool == "" {
			continue
		}
		key := annotationKey(rep.Server, t.Tool)
		if t.State == event.MCPStateRemoved {
			delete(c.ann.byTool, key)
			continue
		}
		if _, known := c.ann.byTool[key]; !known && len(c.ann.byTool) >= maxAnnotatedTools {
			continue
		}
		c.ann.byTool[key] = t.Annotations
	}
}

func (c *Collector) annotationsFor(server, tool string) (event.Annotations, bool) {
	c.annMu.Lock()
	defer c.annMu.Unlock()
	a, ok := c.ann.byTool[annotationKey(server, tool)]
	return a, ok
}
