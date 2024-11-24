package filtermid

import (
	"slices"
	"strconv"

	"github.com/Macmod/ldapx/parser"
)

/*
	Bitwise FilterMiddlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func hasSingleOneBit(n int64) bool {
	return n > 0 && (n&(n-1)) == 0
}

func ExactBitwiseBreakoutFilterObf() func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterEqualityMatch); ok {
			tokenType, err := parser.GetAttributeTokenFormat(f.AttributeDesc)
			if err != nil || !slices.Contains(parser.NumberFormats, tokenType) {
				return f
			}

			if val, err := strconv.ParseUint(f.AssertionValue, 10, 32); err == nil {
				return &parser.FilterAnd{
					Filters: []parser.Filter{
						&parser.FilterExtensibleMatch{
							MatchingRule:  "1.2.840.113556.1.4.803",
							AttributeDesc: f.AttributeDesc,
							MatchValue:    f.AssertionValue,
						},
						&parser.FilterNot{
							Filter: &parser.FilterExtensibleMatch{
								MatchingRule:  "1.2.840.113556.1.4.804",
								AttributeDesc: f.AttributeDesc,
								MatchValue:    strconv.FormatUint(uint64(^uint32(val)), 10),
							},
						},
					},
				}
			}
		}
		return filter
	})
}

func BitwiseDecomposeFilterObf(maxBits int, invert bool) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterExtensibleMatch); ok {
			if val, err := strconv.ParseInt(f.MatchValue, 10, 32); err == nil {
				var filters []parser.Filter
				bitsFound := 0
				remainingBits := val

				for i := 0; i < 31 && bitsFound < maxBits-1; i++ {
					if val&(1<<i) != 0 {
						bitValue := int64(1 << i)
						bitFilter := &parser.FilterExtensibleMatch{
							MatchingRule:  f.MatchingRule,
							AttributeDesc: f.AttributeDesc,
							MatchValue:    strconv.FormatInt(bitValue, 10),
						}
						filters = append(filters, bitFilter)
						remainingBits &= ^bitValue
						bitsFound++
					}
				}

				if remainingBits != 0 {
					filters = append(filters, &parser.FilterExtensibleMatch{
						MatchingRule:  f.MatchingRule,
						AttributeDesc: f.AttributeDesc,
						MatchValue:    strconv.FormatInt(remainingBits, 10),
					})
				}

				if len(filters) > 1 {
					if f.MatchingRule == "1.2.840.113556.1.4.803" {
						return &parser.FilterAnd{Filters: filters}
					} else if f.MatchingRule == "1.2.840.113556.1.4.804" {
						return &parser.FilterOr{Filters: filters}
					}
				} else if len(filters) == 1 {
					return filters[0]
				}
			}
		}
		return filter
	})
}
