package m0report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/classify"
)

// topOther is how many of the commands most often classed other the report names.
const topOther = 10

// Commands is how the Bash and PowerShell calls in the spool were classed. It is not an M0 criterion:
// it is how the cohort review finds what the classifier does not know. A command classed other runs
// something the classifier cannot name, or names a tool it has no class for; when the most common of
// those is a runner (a tool that starts another command) or a network tool, that is a gap to close.
type Commands struct {
	Total    int            `json:"total"`
	ByClass  map[string]int `json:"by_class"`
	TopOther []NameCount    `json:"top_other,omitempty"`

	other map[string]int
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func (c *Commands) add(class, argv0 string) {
	if c.ByClass == nil {
		c.ByClass = map[string]int{}
		c.other = map[string]int{}
	}
	c.Total++
	c.ByClass[class]++
	if class == classify.ClassOther {
		if argv0 == "" {
			// The classifier could not name the command word: quoted, built at run time, or too
			// long and unknown to be a tool name.
			argv0 = "(unnamed)"
		}
		c.other[argv0]++
	}
}

func (c *Commands) finish() {
	if c.ByClass == nil {
		c.ByClass = map[string]int{} // "by_class": {} for a spool with no commands, not null
	}
	for name, n := range c.other {
		c.TopOther = append(c.TopOther, NameCount{name, n})
	}
	sort.Slice(c.TopOther, func(i, j int) bool {
		if c.TopOther[i].Count != c.TopOther[j].Count {
			return c.TopOther[i].Count > c.TopOther[j].Count
		}
		return c.TopOther[i].Name < c.TopOther[j].Name
	})
	if len(c.TopOther) > topOther {
		c.TopOther = c.TopOther[:topOther]
	}
}

// classOrder lists the classes from the most a command can do to the least, as the report prints them.
var classOrder = []string{classify.ClassPublish, classify.ClassVCSWrite, classify.ClassNetwork, classify.ClassFilesystem, classify.ClassOther, classify.ClassReadOnly}

func (c *Commands) writeText(p func(string, ...any)) {
	p("Bash and PowerShell commands (classifier coverage; not an M0 criterion)")
	if c.Total == 0 {
		p("  none in the spool")
		return
	}
	parts := make([]string, 0, len(classOrder))
	for _, class := range classOrder {
		if n := c.ByClass[class]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", class, n))
		}
	}
	p("  %d commands: %s", c.Total, strings.Join(parts, ", "))
	if len(c.TopOther) > 0 {
		names := make([]string, len(c.TopOther))
		for i, nc := range c.TopOther {
			names[i] = fmt.Sprintf("%s %d", nc.Name, nc.Count)
		}
		p("  most often classed other: %s", strings.Join(names, ", "))
		p("  a runner or network tool among these is a classifier gap; see internal/classify")
	}
}
