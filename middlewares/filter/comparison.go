package filtermid

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/parser"
)

/*
	Comparison Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

const CharOrdering = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// TODO: Review
func getNextString(s string) string {
	// Convert string to rune slice for easier manipulation
	chars := []rune(s)

	// Start from rightmost character
	for i := len(chars) - 1; i >= 0; i-- {
		// Find current char position in CharOrdering
		pos := strings.IndexRune(CharOrdering, chars[i])

		// If not last char in CharOrdering, increment to next
		if pos < len(CharOrdering)-1 {
			chars[i] = rune(CharOrdering[pos+1])
			return string(chars)
		}

		// If last char in CharOrdering, set to first char and continue left
		chars[i] = rune(CharOrdering[0])
	}

	// If all chars were last in CharOrdering, append first char
	return s + string(CharOrdering[0])
}

func getPreviousString(s string) string {
	chars := []rune(s)

	for i := len(chars) - 1; i >= 0; i-- {
		pos := strings.IndexRune(CharOrdering, chars[i])

		if pos > 0 {
			chars[i] = rune(CharOrdering[pos-1])
			return string(chars)
		}

		chars[i] = rune(CharOrdering[len(CharOrdering)-1])
	}

	// If string is all first chars, remove first char
	if len(s) > 1 {
		return s[:len(s)-1]
	}

	return s
}

func getNextSID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 1 {
		return sid
	}

	if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
		parts[len(parts)-1] = strconv.Itoa(num + 1)
	}
	return strings.Join(parts, "-")
}

func getPreviousSID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 1 {
		return sid
	}

	if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil && num > 0 {
		parts[len(parts)-1] = strconv.Itoa(num - 1)
	}
	return strings.Join(parts, "-")
}

func EqualityByInclusionFilterObf() func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterEqualityMatch); ok {
			tokenType, err := parser.GetAttributeTokenFormat(f.AttributeDesc)
			if err != nil {
				return f
			}

			var valMinusOne, valPlusOne string
			if tokenType == parser.TokenSID {
				if strings.Count(f.AssertionValue, "-") <= 2 {
					return f
				}

				valMinusOne = getPreviousSID(f.AssertionValue)
				valPlusOne = getNextSID(f.AssertionValue)
			} else if slices.Contains(parser.NumberFormats, tokenType) {
				if val, err := strconv.Atoi(f.AssertionValue); err == nil {
					valMinusOne = strconv.Itoa(val - 1)
					valPlusOne = strconv.Itoa(val + 1)
				}
			} else if tokenType == parser.TokenStringUnicode {
				valMinusOne = getPreviousString(f.AssertionValue)
				valPlusOne = getNextString(f.AssertionValue)
			}
			return &parser.FilterAnd{
				Filters: []parser.Filter{
					&parser.FilterGreaterOrEqual{
						AttributeDesc:  f.AttributeDesc,
						AssertionValue: valMinusOne,
					},
					&parser.FilterLessOrEqual{
						AttributeDesc:  f.AttributeDesc,
						AssertionValue: valPlusOne,
					},
					&parser.FilterNot{
						Filter: &parser.FilterEqualityMatch{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: valMinusOne,
						},
					},
					&parser.FilterNot{
						Filter: &parser.FilterEqualityMatch{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: valPlusOne,
						},
					},
				},
			}
		}
		return filter
	})
}

func EqualityByExclusionFilterObf() func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterEqualityMatch); ok {
			tokenType, err := parser.GetAttributeTokenFormat(f.AttributeDesc)
			if err != nil {
				return f
			}

			var valMinusOne, valPlusOne string
			if tokenType == parser.TokenSID {
				if strings.Count(f.AssertionValue, "-") <= 2 {
					return f
				}
				valMinusOne = getPreviousSID(f.AssertionValue)
				valPlusOne = getNextSID(f.AssertionValue)
			} else if slices.Contains(parser.NumberFormats, tokenType) {
				if val, err := strconv.Atoi(f.AssertionValue); err == nil {
					valMinusOne = strconv.Itoa(val - 1)
					valPlusOne = strconv.Itoa(val + 1)
				}
			} else if tokenType == parser.TokenStringUnicode {
				valMinusOne = getPreviousString(f.AssertionValue)
				valPlusOne = getNextString(f.AssertionValue)
			}

			return &parser.FilterAnd{
				Filters: []parser.Filter{
					&parser.FilterPresent{
						AttributeDesc: f.AttributeDesc,
					},
					&parser.FilterNot{
						Filter: &parser.FilterLessOrEqual{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: valMinusOne,
						},
					},
					&parser.FilterNot{
						Filter: &parser.FilterGreaterOrEqual{
							AttributeDesc:  f.AttributeDesc,
							AssertionValue: valPlusOne,
						},
					},
				},
			}
		}
		return filter
	})
}
