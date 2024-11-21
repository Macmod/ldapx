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

func generateGarbageString(n int) string {
	chars := "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	result := make([]byte, n)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func generateGarbageFilter(attr string) parser.Filter {
	garbageTypes := []func() parser.Filter{
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10)
			}

			return &parser.FilterEqualityMatch{
				AttributeDesc:  attrName,
				AssertionValue: generateGarbageString(10),
			}
		},
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10)
			}

			return &parser.FilterSubstring{
				AttributeDesc: attrName,
				Substrings: []parser.SubstringFilter{
					{Initial: generateGarbageString(10), Any: []string{generateGarbageString(4)}, Final: generateGarbageString(3)},
				},
			}
		},
		func() parser.Filter {
			var attrName string
			if attr != "" {
				attrName = attr
			} else {
				attrName = generateGarbageString(10)
			}

			return &parser.FilterExtensibleMatch{
				MatchingRule:  generateGarbageString(10),
				AttributeDesc: attrName,
				MatchValue:    generateGarbageString(10),
			}
		},
	}

	return garbageTypes[rand.Intn(len(garbageTypes))]()
}

func RandGarbageFilterObf(numGarbage int) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		garbageFilters := make([]parser.Filter, numGarbage+1)
		garbageFilters[0] = filter
		for i := 1; i <= numGarbage; i++ {
			garbageFilters[i] = generateGarbageFilter("")
		}
		return &parser.FilterOr{Filters: garbageFilters}
	})
}
