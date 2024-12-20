package filter

import (
	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
)

// FilterMiddleware is a function that takes a Filter and returns a new Filter
type FilterMiddleware func(parser.Filter) parser.Filter

type FilterMiddlewareDefinition struct {
	Name string
	Func func() FilterMiddleware
}

type FilterMiddlewareChain struct {
	Middlewares []FilterMiddlewareDefinition
}

func (c *FilterMiddlewareChain) Add(m FilterMiddlewareDefinition) {
	c.Middlewares = append(c.Middlewares, m)
}

func (c *FilterMiddlewareChain) Execute(f parser.Filter, verbose bool) parser.Filter {
	current := f
	for _, middleware := range c.Middlewares {
		if verbose {
			log.Log.Printf("[+] Applying middleware on Filter: %s\n", middleware.Name)
		}
		current = middleware.Func()(current)
	}
	return current
}
