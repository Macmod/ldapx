package filtermid

import (
	"math/rand"

	"github.com/Macmod/ldapx/parser"
)

/*
	Garbage Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func generateGarbageString(n int, chars string) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// TODO: Improve with other tricks
func generateGarbageFilter(attr string, chars string) parser.Filter {
	garbageTypes := []func() parser.Filter{
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10, chars)
			}

			return &parser.FilterEqualityMatch{
				AttributeDesc:  attrName,
				AssertionValue: generateGarbageString(10, chars),
			}
		},
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10, chars)
			}

			return &parser.FilterSubstring{
				AttributeDesc: attrName,
				Substrings: []parser.SubstringFilter{
					{Initial: generateGarbageString(10, chars), Any: []string{generateGarbageString(4, chars)}, Final: generateGarbageString(3, chars)},
				},
			}
		},
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10, chars)
			}

			return &parser.FilterExtensibleMatch{
				MatchingRule:  generateGarbageString(10, chars),
				AttributeDesc: attrName,
				MatchValue:    generateGarbageString(10, chars),
			}
		},
	}

	return garbageTypes[rand.Intn(len(garbageTypes))]()
}

func RandGarbageFilterObf(numGarbage int, charset string) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		garbageFilters := make([]parser.Filter, numGarbage+1)
		garbageFilters[0] = filter
		for i := 1; i <= numGarbage; i++ {
			garbageFilters[i] = generateGarbageFilter("", charset)
		}
		return &parser.FilterOr{Filters: garbageFilters}
	})
}
