package main

import (
	"github.com/Macmod/ldapx/parser"
)

func TransformSearchRequest(filter parser.Filter, baseDN string, attrs []string) (parser.Filter, string, []string) {
	newFilter := fc.Execute(filter, true)
	newAttrs := ac.Execute(attrs, true)
	newBaseDN := bc.Execute(baseDN, true)
	return newFilter, newBaseDN, newAttrs

}

func TransformAddRequest(targetDN string) string {
	return bc.Execute(targetDN, true)
}

func TransformModifyRequest(targetDN string) string {
	return bc.Execute(targetDN, true)
}

func TransformDeleteRequest(targetDN string) string {
	return bc.Execute(targetDN, true)
}
