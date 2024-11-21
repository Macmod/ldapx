package filtermid

import (
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

const alphabet = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// TODO: Review
func getNextString(s string) string {
	// Convert string to rune slice for easier manipulation
	chars := []rune(s)

	// Start from rightmost character
	for i := len(chars) - 1; i >= 0; i-- {
		// Find current char position in alphabet
		pos := strings.IndexRune(alphabet, chars[i])

		// If not last char in alphabet, increment to next
		if pos < len(alphabet)-1 {
			chars[i] = rune(alphabet[pos+1])
			return string(chars)
		}

		// If last char in alphabet, set to first char and continue left
		chars[i] = rune(alphabet[0])
	}

	// If all chars were last in alphabet, append first char
	return s + string(alphabet[0])
}

func getPreviousString(s string) string {
	chars := []rune(s)

	for i := len(chars) - 1; i >= 0; i-- {
		pos := strings.IndexRune(alphabet, chars[i])

		if pos > 0 {
			chars[i] = rune(alphabet[pos-1])
			return string(chars)
		}

		chars[i] = rune(alphabet[len(alphabet)-1])
	}

	// If string is all first chars, remove first char
	if len(s) > 1 {
		return s[:len(s)-1]
	}

	return s
}

// TODO: Don't apply for some attribute names like aNR, memberOf, objectCategory...
func EqualityByInclusionFilterObf() func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		if f, ok := filter.(*parser.FilterEqualityMatch); ok {
			var valMinusOne, valPlusOne string
			if val, err := strconv.Atoi(f.AssertionValue); err == nil {
				valMinusOne = strconv.Itoa(val - 1)
				valPlusOne = strconv.Itoa(val + 1)
			} else {
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
			var valMinusOne, valPlusOne string
			if val, err := strconv.Atoi(f.AssertionValue); err == nil {
				valMinusOne = strconv.Itoa(val - 1)
				valPlusOne = strconv.Itoa(val + 1)
			} else {
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
