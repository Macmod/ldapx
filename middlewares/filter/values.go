package filtermid

import (
	"math/rand"
	"slices"
	"strings"

	"github.com/Macmod/ldapx/parser"
)

/*
	Value Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func splitSlice[T any](slice []T, idx int) ([]T, []T) {
	before := make([]T, idx)
	after := make([]T, len(slice)-idx-1)

	copy(before, slice[:idx])
	copy(after, slice[idx+1:])

	return before, after
}

func ApproxMatchFilterObf() FilterMiddleware {
	return LeafApplierFilterMiddleware(
		func(filter parser.Filter) parser.Filter {
			switch f := filter.(type) {
			case *parser.FilterEqualityMatch:
				return &parser.FilterApproxMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: f.AssertionValue,
				}
			default:
				return filter
			}
		},
	)
}

func RandHexValueFilterObf(prob float32) func(parser.Filter) parser.Filter {
	applyHexEncoding := func(attr string, value string) string {
		tokenFormat, err := parser.GetAttributeTokenFormat(attr)
		if err == nil && tokenFormat == parser.TokenStringUnicode {
			return RandomlyHexEncodeString(value, prob)
		}
		return value
	}

	applier := LeafApplierFilterMiddleware(
		func(filter parser.Filter) parser.Filter {
			switch f := filter.(type) {
			case *parser.FilterEqualityMatch:
				return &parser.FilterEqualityMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: applyHexEncoding(f.AttributeDesc, f.AssertionValue),
				}

			case *parser.FilterSubstring:
				newSubstrings := make([]parser.SubstringFilter, len(f.Substrings))
				for i, sub := range f.Substrings {
					newSubstrings[i] = parser.SubstringFilter{
						Initial: applyHexEncoding("name", sub.Initial),
						Any:     applyHexEncoding("name", sub.Any),
						Final:   applyHexEncoding("name", sub.Final),
					}
				}
				return &parser.FilterSubstring{
					AttributeDesc: f.AttributeDesc,
					Substrings:    newSubstrings,
				}

			case *parser.FilterGreaterOrEqual:
				return &parser.FilterGreaterOrEqual{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: applyHexEncoding(f.AttributeDesc, f.AssertionValue),
				}

			case *parser.FilterLessOrEqual:
				return &parser.FilterLessOrEqual{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: applyHexEncoding(f.AttributeDesc, f.AssertionValue),
				}

			case *parser.FilterApproxMatch:
				return &parser.FilterApproxMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: applyHexEncoding(f.AttributeDesc, f.AssertionValue),
				}

			case *parser.FilterExtensibleMatch:
				return &parser.FilterExtensibleMatch{
					MatchingRule:  f.MatchingRule,
					AttributeDesc: f.AttributeDesc,
					MatchValue:    applyHexEncoding(f.AttributeDesc, f.MatchValue),
					DNAttributes:  f.DNAttributes,
				}

			default:
				return filter
			}
		},
	)

	return applier
}

// TODO: Simplify (are ExtensibleMatches possible for timestamp attributes?)
func RandTimestampSuffixFilterObf(prepend bool, append bool, maxChars int) func(parser.Filter) parser.Filter {
	replaceTimestampFixed := func(value string) string {
		return ReplaceTimestamp(value, prepend, append, maxChars)
	}

	applier := LeafApplierFilterMiddleware(
		func(filter parser.Filter) parser.Filter {
			switch f := filter.(type) {
			case *parser.FilterEqualityMatch:
				return &parser.FilterEqualityMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: replaceTimestampFixed(f.AssertionValue),
				}
			case *parser.FilterGreaterOrEqual:
				return &parser.FilterGreaterOrEqual{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: replaceTimestampFixed(f.AssertionValue),
				}

			case *parser.FilterLessOrEqual:
				return &parser.FilterLessOrEqual{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: replaceTimestampFixed(f.AssertionValue),
				}

			case *parser.FilterApproxMatch:
				return &parser.FilterApproxMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: replaceTimestampFixed(f.AssertionValue),
				}

			case *parser.FilterExtensibleMatch:
				return &parser.FilterExtensibleMatch{
					MatchingRule:  f.MatchingRule,
					AttributeDesc: f.AttributeDesc,
					MatchValue:    replaceTimestampFixed(f.MatchValue),
					DNAttributes:  f.DNAttributes,
				}
			}
			return filter
		},
	)

	return applier
}

// Prepended 0's FilterObf
func RandPrependZerosFilterObf(maxZeros int) func(parser.Filter) parser.Filter {
	prependZerosFixed := func(attrName string, value string) string {
		tokenFormat, err := parser.GetAttributeTokenFormat(attrName)
		if err != nil {
			return value
		}

		numberFormats := []parser.LDAPTokenFormat{parser.TokenIntEnumeration, parser.TokenIntTimeInterval, parser.TokenBitwise}
		if slices.Contains(numberFormats, tokenFormat) {
			return PrependZerosToNumber(value, maxZeros)
		} else if tokenFormat == parser.TokenSID {
			return PrependZerosToSID(value, maxZeros)
		}

		return value
	}

	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterEqualityMatch:
			return &parser.FilterEqualityMatch{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AttributeDesc, f.AssertionValue),
			}
		case *parser.FilterGreaterOrEqual:
			return &parser.FilterGreaterOrEqual{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AttributeDesc, f.AssertionValue),
			}
		case *parser.FilterLessOrEqual:
			return &parser.FilterLessOrEqual{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AttributeDesc, f.AssertionValue),
			}
		case *parser.FilterApproxMatch:
			return &parser.FilterApproxMatch{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AttributeDesc, f.AssertionValue),
			}
		case *parser.FilterExtensibleMatch:
			return &parser.FilterExtensibleMatch{
				MatchingRule:  f.MatchingRule,
				AttributeDesc: f.AttributeDesc,
				MatchValue:    prependZerosFixed(f.AttributeDesc, f.MatchValue),
				DNAttributes:  f.DNAttributes,
			}
		}
		return filter
	})
}

func RandSpacingFilterObf(maxSpaces int) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(f parser.Filter) parser.Filter {
		switch v := f.(type) {
		case *parser.FilterEqualityMatch:
			tokenType, err := parser.GetAttributeTokenFormat(v.AttributeDesc)

			if err != nil {
				return f
			}

			if strings.ToLower(v.AttributeDesc) == "anr" {
				v.AssertionValue = AddANRSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenDNString {
				v.AssertionValue = AddDNSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenSID {
				v.AssertionValue = AddSIDSpacing(v.AssertionValue, maxSpaces)
			}
		case *parser.FilterSubstring:
			if v.AttributeDesc == "aNR" {
				for i := range v.Substrings {
					if v.Substrings[i].Initial != "" {
						v.Substrings[i].Initial = AddANRSpacing(v.Substrings[i].Initial, maxSpaces)
					}
					if v.Substrings[i].Final != "" {
						v.Substrings[i].Final = AddANRSpacing(v.Substrings[i].Final, maxSpaces)
					}
				}
			}
		case *parser.FilterGreaterOrEqual:
			attrName := strings.ToLower(v.AttributeDesc)
			tokenType, err := parser.GetAttributeTokenFormat(attrName)

			if err != nil {
				return f
			}

			if attrName == "anr" {
				v.AssertionValue = AddANRSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenSID {
				v.AssertionValue = AddSIDSpacing(v.AssertionValue, maxSpaces)
			}
		case *parser.FilterLessOrEqual:
			attrName := strings.ToLower(v.AttributeDesc)
			tokenType, err := parser.GetAttributeTokenFormat(attrName)

			if err != nil {
				return f
			}

			if attrName == "anr" {
				v.AssertionValue = AddANRSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenSID {
				v.AssertionValue = AddSIDSpacing(v.AssertionValue, maxSpaces)
			}
		case *parser.FilterApproxMatch:
			tokenType, err := parser.GetAttributeTokenFormat(v.AttributeDesc)
			attrName := strings.ToLower(v.AttributeDesc)

			if err != nil {
				return f
			}

			if attrName == "anr" {
				v.AssertionValue = AddANRSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenDNString {
				v.AssertionValue = AddDNSpacing(v.AssertionValue, maxSpaces)
			} else if tokenType == parser.TokenSID {
				v.AssertionValue = AddSIDSpacing(v.AssertionValue, maxSpaces)
			}
		}
		return f
	})
}

func RandAddWildcardFilterObf(prob float32) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterEqualityMatch:
			if rand.Float32() < prob {
				// Only apply to string attributes
				tokenType, err := parser.GetAttributeTokenFormat(f.AttributeDesc)
				if err == nil && tokenType == parser.TokenStringUnicode {
					chars := []rune(f.AssertionValue)
					splitPoint := rand.Intn(len(chars) + 1)

					return &parser.FilterSubstring{
						AttributeDesc: f.AttributeDesc,
						Substrings: []parser.SubstringFilter{{
							Initial: string(chars[:splitPoint]),
							Final:   string(chars[splitPoint:]),
						}},
					}
				}
			}
			return f

		case *parser.FilterSubstring:
			if rand.Float32() < prob && len(f.Substrings) > 0 {
				// Pick a random substring and split it
				subIdx := rand.Intn(len(f.Substrings))
				sub := f.Substrings[subIdx]

				if sub.Initial != "" {
					// Grab a suffix and put it in the next Any
					sliceBefore, sliceAfter := splitSlice(f.Substrings, subIdx)

					splitPoint := rand.Intn(len(sub.Initial))
					//fmt.Printf("Initial split point %d\n", splitPoint)
					suffix := sub.Initial[splitPoint:]
					sub.Initial = sub.Initial[:splitPoint]

					f.Substrings = append(
						append(
							sliceBefore,
							sub,
							parser.SubstringFilter{Any: suffix},
						),
						sliceAfter...,
					)
				} else if len(sub.Any) > 1 {
					// If there's an any, we assume that there's Initial, Any and Final
					// Grab a suffix and put it in the next Any
					sliceBefore, sliceAfter := splitSlice(f.Substrings, subIdx)

					splitPoint := rand.Intn(len(sub.Any)-1) + 1
					//fmt.Printf("Any split point %d\n", splitPoint)
					suffix := sub.Any[splitPoint:]
					sub.Any = sub.Any[:splitPoint]

					f.Substrings = append(
						append(
							sliceBefore,
							sub,
							parser.SubstringFilter{Any: suffix},
						),
						sliceAfter...,
					)
				} else if sub.Final != "" {
					// Grab a prefix and put it in a previous Any
					sliceBefore, sliceAfter := splitSlice(f.Substrings, subIdx)

					splitPoint := rand.Intn(len(sub.Final)) + 1
					//fmt.Printf("Final split point %d\n", splitPoint)
					prefix := sub.Final[:splitPoint]
					sub.Final = sub.Final[splitPoint:]

					f.Substrings = append(
						append(
							sliceBefore,
							parser.SubstringFilter{Any: prefix},
							sub,
						),
						sliceAfter...,
					)
				}
			}

			return f

		default:
			return filter
		}
	})
}
