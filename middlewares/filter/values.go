package filtermid

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"

	"github.com/Macmod/ldapx/parser"
)

/*
	Leaf Value Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

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

// Hex Encoding FilterObf
func hexEncodeChar(c rune) string {
	return fmt.Sprintf("\\%02x", c)
}

func randomlyHexEncodeString(s string, prob float32) string {
	var result strings.Builder
	for _, c := range s {
		if rand.Float32() < prob {
			result.WriteString(hexEncodeChar(c))
		} else {
			result.WriteRune(c)
		}
	}

	return result.String()
}

func RandHexValueFilterObf(prob float32) func(parser.Filter) parser.Filter {
	applyHexEncoding := func(attr string, value string) string {
		tokenFormat, err := parser.GetAttributeTokenFormat(attr)
		if err == nil && tokenFormat == parser.TokenStringUnicode {
			return randomlyHexEncodeString(value, prob)
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
						Final:   applyHexEncoding("name", sub.Final),
					}

					newAny := make([]string, len(sub.Any))
					for j, _any := range sub.Any {
						newAny[j] = applyHexEncoding("name", _any)
					}
					newSubstrings[i].Any = newAny
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

// Timestamp Suffix FilterObf
func getSomeRandChars(maxChars int) []rune {
	numChars := rand.Intn(maxChars)
	randomChars := make([]rune, numChars)

	for i := range randomChars {
		// ASCII printable characters range: 33-126
		randomChars[i] = rune(rand.Intn(94) + 33)
	}

	return randomChars
}

func replaceTimestamp(value string, prepend bool, append bool, maxChars int) string {
	re := regexp.MustCompile(`(\d{14})\.(\d*)Z$`) // TODO: What about leading zeros?
	return re.ReplaceAllStringFunc(value, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 3 {
			var prependStr string
			var appendStr string

			if prepend {
				prependStr = string(getSomeRandChars(maxChars))
			}

			if append {
				appendStr = string(getSomeRandChars(maxChars))
			}

			return fmt.Sprintf("%s.%s%sZ%s", parts[1], parts[2], prependStr, appendStr)
		}
		return match
	})
}

func RandTimestampSuffixFilterObf(prepend bool, append bool, maxChars int) func(parser.Filter) parser.Filter {
	replaceTimestampFixed := func(value string) string {
		return replaceTimestamp(value, prepend, append, maxChars)
	}

	applier := LeafApplierFilterMiddleware(
		func(filter parser.Filter) parser.Filter {
			switch f := filter.(type) {
			case *parser.FilterEqualityMatch:
				return &parser.FilterEqualityMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: replaceTimestampFixed(f.AssertionValue),
				}
			case *parser.FilterSubstring:
				newSubstrings := make([]parser.SubstringFilter, len(f.Substrings))
				for i, sub := range f.Substrings {
					newSubstrings[i] = parser.SubstringFilter{
						Initial: replaceTimestampFixed(sub.Initial),
						Final:   replaceTimestampFixed(sub.Final),
					}
					newAny := make([]string, len(sub.Any))
					for j, _any := range sub.Any {
						newAny[j] = replaceTimestampFixed(_any)
					}
					newSubstrings[i].Any = newAny
				}
				return &parser.FilterSubstring{
					AttributeDesc: f.AttributeDesc,
					Substrings:    newSubstrings,
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
func prependZeros(input string, maxZeros int) string {
	numZeros := rand.Intn(maxZeros)
	if len(input) > 0 && input[0] == '-' {
		zeros := strings.Repeat("0", numZeros)
		return "-" + zeros + input[1:]
	}

	return strings.Repeat("0", numZeros) + input
}

func RandPrependedZerosFilterObf(maxZeros int) func(parser.Filter) parser.Filter {
	prependZerosFixed := func(value string) string {
		return prependZeros(value, maxZeros)
	}

	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandPrependedZerosFilterObf(maxZeros)(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandPrependedZerosFilterObf(maxZeros)(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: RandPrependedZerosFilterObf(maxZeros)(f.Filter)}

		case *parser.FilterEqualityMatch:
			return &parser.FilterEqualityMatch{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AssertionValue),
			}

		case *parser.FilterSubstring:
			newSubstrings := make([]parser.SubstringFilter, len(f.Substrings))
			for i, sub := range f.Substrings {
				newSubstrings[i] = parser.SubstringFilter{
					Initial: prependZerosFixed(sub.Initial),
					Final:   prependZerosFixed(sub.Final),
				}
				newAny := make([]string, len(sub.Any))
				for j, _any := range sub.Any {
					newAny[j] = prependZerosFixed(_any)
				}
				newSubstrings[i].Any = newAny
			}
			return &parser.FilterSubstring{
				AttributeDesc: f.AttributeDesc,
				Substrings:    newSubstrings,
			}

		case *parser.FilterGreaterOrEqual:
			return &parser.FilterGreaterOrEqual{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AssertionValue),
			}

		case *parser.FilterLessOrEqual:
			return &parser.FilterLessOrEqual{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AssertionValue),
			}

		case *parser.FilterApproxMatch:
			return &parser.FilterApproxMatch{
				AttributeDesc:  f.AttributeDesc,
				AssertionValue: prependZerosFixed(f.AssertionValue),
			}

		case *parser.FilterExtensibleMatch:
			return &parser.FilterExtensibleMatch{
				MatchingRule:  f.MatchingRule,
				AttributeDesc: f.AttributeDesc,
				MatchValue:    prependZerosFixed(f.MatchValue),
				DNAttributes:  f.DNAttributes,
			}
		}
		return filter
	}
}

// TODO: Investigate how to get this working!
func RandSpacingFilterObf(maxSpaces int) func(f parser.Filter) parser.Filter {
	return func(f parser.Filter) parser.Filter {
		switch v := f.(type) {
		case *parser.FilterEqualityMatch:
			v.AssertionValue = addRandSpacing(v.AssertionValue, maxSpaces)
		case *parser.FilterAnd:
			for i := range v.Filters {
				v.Filters[i] = RandSpacingFilterObf(maxSpaces)(v.Filters[i])
			}
		case *parser.FilterOr:
			for i := range v.Filters {
				v.Filters[i] = RandSpacingFilterObf(maxSpaces)(v.Filters[i])
			}
		case *parser.FilterNot:
			v.Filter = RandSpacingFilterObf(maxSpaces)(v.Filter)
		case *parser.FilterSubstring:
			for i := range v.Substrings {
				if v.Substrings[i].Initial != "" {
					v.Substrings[i].Initial = addRandSpacing(v.Substrings[i].Initial, maxSpaces)
				}
				for j, _any := range v.Substrings[i].Any {
					v.Substrings[i].Any[j] = addRandSpacing(_any, maxSpaces)
				}
				if v.Substrings[i].Final != "" {
					v.Substrings[i].Final = addRandSpacing(v.Substrings[i].Final, maxSpaces)
				}
			}
		case *parser.FilterGreaterOrEqual:
			v.AssertionValue = addRandSpacing(v.AssertionValue, maxSpaces)
		case *parser.FilterLessOrEqual:
			v.AssertionValue = addRandSpacing(v.AssertionValue, maxSpaces)
		case *parser.FilterApproxMatch:
			v.AssertionValue = addRandSpacing(v.AssertionValue, maxSpaces)
		case *parser.FilterExtensibleMatch:
			v.MatchingRule = addRandSpacing(v.MatchingRule, maxSpaces) // Is this needed?
			v.AttributeDesc = addRandSpacing(v.AttributeDesc, maxSpaces)
			v.MatchValue = addRandSpacing(v.MatchValue, maxSpaces) // Is this needed?
		}
		return f
	}
}

func addRandSpacing(s string, maxSpaces int) string {
	var result strings.Builder
	var numSpaces int
	for _, char := range s {
		numSpaces = rand.Intn(maxSpaces)
		if numSpaces > 0 {
			result.WriteString(strings.Repeat(" ", numSpaces))
		}
		result.WriteRune(char)
	}

	numSpaces = rand.Intn(maxSpaces)
	if numSpaces > 0 {
		result.WriteString(strings.Repeat(" ", numSpaces))
	}

	return result.String()
}

// TODO: Wildcard obfuscation
func RandWildcardFilterObf(prob float32) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(
		func(filter parser.Filter) parser.Filter {
			switch f := filter.(type) {
			case *parser.FilterEqualityMatch:
				// TODO: Review and test this
				if rand.Float32() < prob {
					chars := strings.Split(f.AssertionValue, "")
					substrings := []parser.SubstringFilter{{
						Initial: chars[0],
					}}

					for i := 1; i < len(chars)-1; i++ {
						if rand.Float32() < 0.3 {
							substrings[0].Any = append(substrings[0].Any, chars[i])
						}
					}

					if len(chars) > 1 {
						substrings[0].Final = chars[len(chars)-1]
					}

					return &parser.FilterSubstring{
						AttributeDesc: f.AttributeDesc,
						Substrings:    substrings,
					}
				}
				return f

			default:
				return filter
			}
		},
	)
}
