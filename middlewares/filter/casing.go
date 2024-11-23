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
	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			switch v := f.(type) {
			case *parser.FilterEqualityMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterSubstring:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				for i := range v.Substrings {
					if v.Substrings[i].Initial != "" {
						v.Substrings[i].Initial = randomizeEachChar(v.Substrings[i].Initial, prob)
					}
					if v.Substrings[i].Any != "" {
						v.Substrings[i].Any = randomizeEachChar(v.Substrings[i].Any, prob)
					}
					if v.Substrings[i].Final != "" {
						v.Substrings[i].Final = randomizeEachChar(v.Substrings[i].Final, prob)
					}
				}
				return v
			case *parser.FilterGreaterOrEqual:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterLessOrEqual:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterApproxMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterPresent:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				return v
			case *parser.FilterExtensibleMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.MatchValue = randomizeEachChar(v.MatchValue, prob)
				return v
			}
			return f
		},
	)
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
