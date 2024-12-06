package basedn

import "log"

// BaseDNMiddleware is a function that takes a BaseDN string and returns a new one
type BaseDNMiddleware func(string) string

type BaseDNMiddlewareDefinition struct {
	Name string
	Func func() BaseDNMiddleware
}

type BaseDNMiddlewareChain struct {
	Middlewares []BaseDNMiddlewareDefinition
}

func (c *BaseDNMiddlewareChain) Add(m BaseDNMiddlewareDefinition) {
	c.Middlewares = append(c.Middlewares, m)
}

func (c *BaseDNMiddlewareChain) Execute(baseDN string, verbose bool) string {
	current := baseDN
	for _, middleware := range c.Middlewares {
		if verbose {
			log.Printf("[+] Applying middleware on BaseDN: %s\n", middleware.Name)
		}
		current = middleware.Func()(current)
	}
	return current
}
