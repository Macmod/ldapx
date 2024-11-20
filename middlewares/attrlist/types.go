package attrlistmid

import "log"

// AttrListMiddleware is a function that takes a list of attributes and returns a new list
type AttrListMiddleware func([]string) []string

type AttrListMiddlewareDefinition struct {
	Name string
	Func AttrListMiddleware
}

type AttrListMiddlewareChain struct {
	Middlewares []AttrListMiddlewareDefinition
}

func (c *AttrListMiddlewareChain) Add(m AttrListMiddlewareDefinition) {
	c.Middlewares = append(c.Middlewares, m)
}

func (c *AttrListMiddlewareChain) Execute(attrs []string, verbose bool) []string {
	current := attrs
	for _, middleware := range c.Middlewares {
		if verbose {
			log.Printf("[+] Applying middleware: %s\n", middleware.Name)
		}
		current = middleware.Func(current)
	}
	return current
}
