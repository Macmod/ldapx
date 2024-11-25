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

func GenerateGarbageFilter(attr string, garbageSize int, chars string) parser.Filter {
	garbageFixed := func() string {
		return GenerateGarbageString(garbageSize, chars)
	}

	equalityGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		return &parser.FilterEqualityMatch{
			AttributeDesc:  attrName,
			AssertionValue: garbageFixed(),
		}
	}

	approxMatchGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		return &parser.FilterApproxMatch{
			AttributeDesc:  attrName,
			AssertionValue: garbageFixed(),
		}
	}

	substringGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		substrings := []parser.SubstringFilter{}

		// Randomly select the substring pattern
		pattern := rand.Intn(4)

		switch pattern {
		case 0:
			// Initial only
			substrings = append(substrings, parser.SubstringFilter{Initial: garbageFixed()})
		case 1:
			// Final only
			substrings = append(substrings, parser.SubstringFilter{Final: garbageFixed()})
		case 2:
			// Initial and Final
			substrings = append(substrings, parser.SubstringFilter{Initial: garbageFixed()})
			substrings = append(substrings, parser.SubstringFilter{Final: garbageFixed()})
		case 3:
			// Initial, random number of Any's, and optionally a Final
			substrings = append(substrings, parser.SubstringFilter{Initial: garbageFixed()})

			numAny := rand.Intn(3)
			for i := 0; i < numAny; i++ {
				substrings = append(substrings, parser.SubstringFilter{Any: garbageFixed()})
			}

			if rand.Float32() < 0.5 {
				substrings = append(substrings, parser.SubstringFilter{Final: garbageFixed()})
			}
		}

		return &parser.FilterSubstring{
			AttributeDesc: attrName,
			Substrings:    substrings,
		}
	}

	extensibleMatchGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		return &parser.FilterExtensibleMatch{
			MatchingRule:  garbageFixed(),
			AttributeDesc: attrName,
			MatchValue:    garbageFixed(),
		}
	}

	lessOrEqualGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		return &parser.FilterLessOrEqual{
			AttributeDesc:  attrName,
			AssertionValue: garbageFixed(),
		}
	}

	greaterOrEqualGarbageGenerator := func() parser.Filter {
		var attrName string
		if attr != "" {
			attrName = attr
		} else {
			attrName = garbageFixed()
		}

		return &parser.FilterGreaterOrEqual{
			AttributeDesc:  attrName,
			AssertionValue: garbageFixed(),
		}
	}

	garbageGenerators := []func() parser.Filter{
		equalityGarbageGenerator,
		approxMatchGarbageGenerator,
		substringGarbageGenerator,
		lessOrEqualGarbageGenerator,
		greaterOrEqualGarbageGenerator,
		extensibleMatchGarbageGenerator,
	}

	return garbageGenerators[rand.Intn(len(garbageGenerators))]()
}

func RandGarbageFilterObf(numGarbage int, garbageSize int, charset string) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		garbageFilters := make([]parser.Filter, numGarbage+1)
		garbageFilters[0] = filter
		for i := 1; i <= numGarbage; i++ {
			garbageFilters[i] = GenerateGarbageFilter("", garbageSize, charset)
		}
		return &parser.FilterOr{Filters: garbageFilters}
	})
}
