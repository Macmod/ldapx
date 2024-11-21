package filtermid

import (
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
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = ExactBitwiseBreakoutFilterObf()(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = ExactBitwiseBreakoutFilterObf()(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: ExactBitwiseBreakoutFilterObf()(f.Filter)}

		case *parser.FilterEqualityMatch:
			if val, err := strconv.ParseInt(f.AssertionValue, 10, 64); err == nil {
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
								MatchValue:    strconv.FormatInt(^val, 10),
							},
						},
					},
				}
			}
			return f

		default:
			return filter
		}
	}
}

func BitwiseDecomposeFilterObf(maxBits int, invert bool) func(parser.Filter) parser.Filter {
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = BitwiseDecomposeFilterObf(maxBits, invert)(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = BitwiseDecomposeFilterObf(maxBits, invert)(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: BitwiseDecomposeFilterObf(maxBits, invert)(f.Filter)}

		case *parser.FilterExtensibleMatch:
			if val, err := strconv.ParseInt(f.MatchValue, 10, 32); err == nil {
				var filters []parser.Filter
				bitsFound := 0
				remainingBits := val

				/*
					    TODO: Check is there's anything to be done here
						if invert && hasSingleOneBit(val) {
							invertedVal := ^val
							wrappedFilter := &parser.FilterNot{
								Filter: &parser.FilterExtensibleMatch{
									MatchingRule:  f.MatchingRule,
									AttributeDesc: f.AttributeDesc,
									MatchValue:    strconv.FormatInt(invertedVal, 10),
								},
							}

							return BitwiseDecomposeFilterObf(maxBits, false)(wrappedFilter)
						}*/

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

				// Add remaining bits as a single component if any
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
				} else {
					return filters[0]
				}
			}
			return f

		default:
			return filter
		}
	}
}
