package basedn

import "github.com/Macmod/ldapx/log"

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

// ReferenceOnlyForms are the object-addressing DN forms (MS-ADTS 3.1.1.3.1.2.4)
// that replace a DN with an alternative form naming an already-existing object.
// They only resolve when the DN references such an object, so they must not be
// applied to a DN that names an object to be created or a relative name.
var ReferenceOnlyForms = map[string]bool{
	"SIDFormat":    true,
	"GUIDFormat":   true,
	"WKGUIDFormat": true,
}

// Execute runs the chain over a DN that references an existing object (a search
// base, a Modify/Delete target, a ModifyDN entry or newSuperior).
func (c *BaseDNMiddlewareChain) Execute(baseDN string, verbose bool) string {
	return c.execute(baseDN, verbose, true)
}

// ExecuteSafe runs the chain over a DN that does not reference an existing
// object - an Add entry (named object to be created) or a ModifyDN newRDN
// (relative name) - skipping the object-addressing forms that cannot apply to
// such a field while still running the rest of the chain.
func (c *BaseDNMiddlewareChain) ExecuteSafe(baseDN string, verbose bool) string {
	return c.execute(baseDN, verbose, false)
}

func (c *BaseDNMiddlewareChain) execute(baseDN string, verbose bool, allowReferenceForms bool) string {
	current := baseDN
	for _, middleware := range c.Middlewares {
		if !allowReferenceForms && ReferenceOnlyForms[middleware.Name] {
			if verbose {
				log.Log.Printf("[!] Skipping incompatible BaseDN middleware %s (object-addressing form on a non-reference DN)", middleware.Name)
			}
			continue
		}
		if verbose {
			log.Log.Printf("[+] Applying middleware on BaseDN: %s", middleware.Name)
		}
		current = applyToDNPart(middleware.Func())(current)
	}
	return current
}
