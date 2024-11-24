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
			if val, err := strconv.ParseUint(f.MatchValue, 10, 32); err == nil {
				var filters []parser.Filter
				bitsFound := 0
				remainingBits := val

				for i := 0; i < 31 && bitsFound < maxBits-1; i++ {
					if val&(1<<i) != 0 {
						bitValue := uint64(1 << i)
						bitFilter := &parser.FilterExtensibleMatch{
							MatchingRule:  f.MatchingRule,
							AttributeDesc: f.AttributeDesc,
							MatchValue:    strconv.FormatUint(bitValue, 10),
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
						MatchValue:    strconv.FormatUint(remainingBits, 10),
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

// TODO: Review
func BitwiseExpandPossibleFilterObf() func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterExtensibleMatch); ok {
			if f.MatchingRule != "1.2.840.113556.1.4.803" && f.MatchingRule != "1.2.840.113556.1.4.804" {
				return filter
			}

			targetVal, err := strconv.ParseUint(f.MatchValue, 10, 32)
			if err != nil {
				return filter
			}

			var possibilities []parser.Filter

			// For AND: start with target value and add combinations with additional bits
			if f.MatchingRule == "1.2.840.113556.1.4.803" {
				// Start with minimum required value (target itself)
				possibilities = append(possibilities, &parser.FilterEqualityMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: strconv.FormatUint(targetVal, 10),
				})

				// Add combinations with one extra bit set
				for bit := uint64(0); bit < 32; bit++ {
					if targetVal&(1<<bit) == 0 {
						newVal := targetVal | (1 << bit)
						possibilities = append(possibilities, &parser.FilterEqualityMatch{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: strconv.FormatUint(newVal, 10),
						})
					}
				}
			}

			// For OR: generate combinations using individual set bits
			if f.MatchingRule == "1.2.840.113556.1.4.804" {
				for bit := uint64(0); bit < 32; bit++ {
					if targetVal&(1<<bit) != 0 {
						possibilities = append(possibilities, &parser.FilterEqualityMatch{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: strconv.FormatUint(1<<bit, 10),
						})
					}
				}
			}

			if len(possibilities) > 0 {
				return &parser.FilterOr{Filters: possibilities}
			}
		}
		return filter
	})
}
