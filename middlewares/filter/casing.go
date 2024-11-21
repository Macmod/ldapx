package filtermid

import (
	"math/rand"
	"unicode"

	"github.com/Macmod/ldapx/parser"
)

/*
	Casing FilterMiddlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

// TODO: Avoid attribute types that have specific formats and may break?
func RandCaseFilterObf(prob float32) func(f parser.Filter) parser.Filter {
	return func(f parser.Filter) parser.Filter {
		switch v := f.(type) {
		case *parser.FilterEqualityMatch:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
		case *parser.FilterAnd:
			for i := range v.Filters {
				v.Filters[i] = RandCaseFilterObf(prob)(v.Filters[i])
			}
		case *parser.FilterOr:
			for i := range v.Filters {
				v.Filters[i] = RandCaseFilterObf(prob)(v.Filters[i])
			}
		case *parser.FilterNot:
			v.Filter = RandCaseFilterObf(prob)(v.Filter)
		case *parser.FilterSubstring:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			for i := range v.Substrings {
				if v.Substrings[i].Initial != "" {
					v.Substrings[i].Initial = randomizeEachChar(v.Substrings[i].Initial, prob)
				}
				for j, any := range v.Substrings[i].Any {
					v.Substrings[i].Any[j] = randomizeEachChar(any, prob)
				}
				if v.Substrings[i].Final != "" {
					v.Substrings[i].Final = randomizeEachChar(v.Substrings[i].Final, prob)
				}
			}
		case *parser.FilterGreaterOrEqual:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
		case *parser.FilterLessOrEqual:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
		case *parser.FilterApproxMatch:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
		case *parser.FilterPresent:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
		case *parser.FilterExtensibleMatch:
			v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
			v.MatchValue = randomizeEachChar(v.MatchValue, prob) // Is this needed?
		}
		return f
	}
}

func randomizeEachChar(s string, prob float32) string {
	result := make([]rune, len(s))
	for i, char := range s {
		if rand.Float32() < prob {
			result[i] = unicode.ToUpper(char)
		} else {
			result[i] = unicode.ToLower(char)
		}
	}
	return string(result)
}
