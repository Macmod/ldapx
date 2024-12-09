package attrentries

import (
	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
)

// AttrEntriesMiddleware is a function that takes a list of attribute entries and returns a new list of attribute entries
type AttrEntriesMiddleware func(parser.AttrEntries) parser.AttrEntries

type AttrEntriesMiddlewareDefinition struct {
	Name string
	Func func() AttrEntriesMiddleware
}

type AttrEntriesMiddlewareChain struct {
	Middlewares []AttrEntriesMiddlewareDefinition
}

func (c *AttrEntriesMiddlewareChain) Add(m AttrEntriesMiddlewareDefinition) {
	c.Middlewares = append(c.Middlewares, m)
}

func (c *AttrEntriesMiddlewareChain) Execute(attrEntries parser.AttrEntries, verbose bool) parser.AttrEntries {
	current := attrEntries
	for _, middleware := range c.Middlewares {
		if verbose {
			log.Log.Printf("[+] Applying middleware on AttrEntries: %s\n", middleware.Name)
		}
		current = middleware.Func()(current)
	}
	return current
}
