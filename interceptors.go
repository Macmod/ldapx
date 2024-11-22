package main

import (
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/Macmod/ldapx/parser"
)

func TransformSearchRequest(filter parser.Filter, baseDN string, attrs []string, fc *filtermid.FilterMiddlewareChain, ac *attrlistmid.AttrListMiddlewareChain, bc *basednmid.BaseDNMiddlewareChain) (parser.Filter, string, []string) {
	newFilter := fc.Execute(filter, true)
	newAttrs := ac.Execute(attrs, true)
	newBaseDN := bc.Execute(baseDN, true)
	return newFilter, newBaseDN, newAttrs
}
