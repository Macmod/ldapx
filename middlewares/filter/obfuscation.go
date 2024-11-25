package filtermid

import (
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Macmod/ldapx/parser"
)

/*
	Obfuscation Filter Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

/*
	AttributeName Obfuscation Middlewares
*/

func OIDAttributeFilterObf(maxZeros int, includePrefix bool) func(f parser.Filter) parser.Filter {
	obfuscate := func(attr string) string {
		oid, err := MapToOID(attr)
		if err == nil {
			mapped := PrependZerosToOID(oid, maxZeros)
			if includePrefix {
				mapped = fmt.Sprintf("oID.%s", mapped)
			}
			return mapped
		}
		return attr
	}

	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			switch v := f.(type) {
			case *parser.FilterEqualityMatch:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterSubstring:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterGreaterOrEqual:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterLessOrEqual:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterApproxMatch:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterPresent:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			case *parser.FilterExtensibleMatch:
				v.AttributeDesc = obfuscate(v.AttributeDesc)
			}
			return f
		},
	)
}

func ANRAttributeFilterObf(anrSet []string) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			switch v := f.(type) {
			case *parser.FilterEqualityMatch:
				if slices.Contains(anrSet, strings.ToLower(v.AttributeDesc)) {
					v.AttributeDesc = "aNR"
					v.AssertionValue = "=" + v.AssertionValue
				}
			case *parser.FilterApproxMatch:
				if slices.Contains(anrSet, strings.ToLower(v.AttributeDesc)) {
					v.AttributeDesc = "aNR"
					v.AssertionValue = "=" + v.AssertionValue
				}
			case *parser.FilterGreaterOrEqual:
				if slices.Contains(anrSet, strings.ToLower(v.AttributeDesc)) {
					v.AttributeDesc = "aNR"
					v.AssertionValue = "=" + v.AssertionValue
				}
			case *parser.FilterLessOrEqual:
				if slices.Contains(anrSet, strings.ToLower(v.AttributeDesc)) {
					v.AttributeDesc = "aNR"
					v.AssertionValue = "=" + v.AssertionValue
				}
			}
			return f
		},
	)
}

/*
	Garbage Obfuscation Middlewares
*/

func ANRSubstringGarbageFilterObf(minGarbage int, maxGarbage int, garbageCharset string) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			if em, ok := f.(*parser.FilterEqualityMatch); ok {
				if em.AttributeDesc == "aNR" {
					numGarbage := minGarbage + rand.Intn(maxGarbage-minGarbage+1)
					garbage := make([]byte, numGarbage)
					for i := range garbage {
						garbage[i] = garbageCharset[rand.Intn(len(garbageCharset))]
					}

					return &parser.FilterSubstring{
						AttributeDesc: "aNR",
						Substrings: []parser.SubstringFilter{
							{Initial: em.AssertionValue},
							{Final: string(garbage)},
						},
					}
				}
			}
			return f
		},
	)
}

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

/*
	Comparison Obfuscation Middlewares
*/

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

				valMinusOne = GetPreviousSID(f.AssertionValue)
				valPlusOne = GetNextSID(f.AssertionValue)
			} else if slices.Contains(parser.NumberFormats, tokenType) {
				if val, err := strconv.Atoi(f.AssertionValue); err == nil {
					valMinusOne = strconv.Itoa(val - 1)
					valPlusOne = strconv.Itoa(val + 1)
				}
			} else if tokenType == parser.TokenStringUnicode {
				valMinusOne = GetPreviousString(f.AssertionValue)
				valPlusOne = GetNextString(f.AssertionValue)
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
				valMinusOne = GetPreviousSID(f.AssertionValue)
				valPlusOne = GetNextSID(f.AssertionValue)
			} else if slices.Contains(parser.NumberFormats, tokenType) {
				if val, err := strconv.Atoi(f.AssertionValue); err == nil {
					valMinusOne = strconv.Itoa(val - 1)
					valPlusOne = strconv.Itoa(val + 1)
				}
			} else if tokenType == parser.TokenStringUnicode {
				valMinusOne = GetPreviousString(f.AssertionValue)
				valPlusOne = GetNextString(f.AssertionValue)
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

/*
	Bitwise Obfuscation Middlewares
*/

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

// TODO: Review and implement if it works well

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

/*
	Boolean Obfuscation Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func RandAddBoolFilterObf(maxDepth int, prob float32) func(f parser.Filter) parser.Filter {
	return func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float32() < prob {
				if rand.Intn(2) == 0 {
					// Wrap in AND
					result = &parser.FilterAnd{
						Filters: []parser.Filter{result},
					}
				} else {
					// Wrap in OR
					result = &parser.FilterOr{
						Filters: []parser.Filter{result},
					}
				}
			}
		}

		return result
	}
}

func RandDblNegBoolFilterObf(maxDepth int, prob float32) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float32() < prob {
				// Wrap in NOTs
				result = &parser.FilterNot{
					Filter: &parser.FilterNot{
						Filter: result,
					},
				}
			}
		}

		return result
	})
}

func RandDeMorganBoolFilterObf(prob float32) func(f parser.Filter) parser.Filter {
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		// TODO: Review
		case *parser.FilterAnd:
			// Apply DeMorgan with prob X
			if rand.Float32() < prob {
				// Convert AND to OR using DeMorgan: !(a && b) = !a || !b
				notFilters := make([]parser.Filter, len(f.Filters))
				for i, subFilter := range f.Filters {
					notFilters[i] = &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(subFilter)}
				}
				return &parser.FilterNot{Filter: &parser.FilterOr{Filters: notFilters}}
			}

			// Just recurse on children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandDeMorganBoolFilterObf(prob)(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			// Apply DeMorgan with prob X
			if rand.Float32() < prob {
				// Convert OR to AND using DeMorgan: !(a || b) = !a && !b
				notFilters := make([]parser.Filter, len(f.Filters))
				for i, subFilter := range f.Filters {
					notFilters[i] = &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(subFilter)}
				}
				return &parser.FilterNot{Filter: &parser.FilterAnd{Filters: notFilters}}
			}

			// Just recurse on children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandDeMorganBoolFilterObf(prob)(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(f.Filter)}

		default:
			return filter
		}
	}
}

func RandBoolReorderFilterObf() func(f parser.Filter) parser.Filter {
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			// Create new slice and copy filters
			newFilters := make([]parser.Filter, len(f.Filters))
			copy(newFilters, f.Filters)

			// Fisher-Yates shuffle
			for i := len(newFilters) - 1; i > 0; i-- {
				j := rand.Intn(i + 1)
				newFilters[i], newFilters[j] = newFilters[j], newFilters[i]
			}

			// Recurse on children
			for i, subFilter := range newFilters {
				newFilters[i] = RandBoolReorderFilterObf()(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			// Create new slice and copy filters
			newFilters := make([]parser.Filter, len(f.Filters))
			copy(newFilters, f.Filters)

			// Fisher-Yates shuffle
			for i := len(newFilters) - 1; i > 0; i-- {
				j := rand.Intn(i + 1)
				newFilters[i], newFilters[j] = newFilters[j], newFilters[i]
			}

			// Recurse on children
			for i, subFilter := range newFilters {
				newFilters[i] = RandBoolReorderFilterObf()(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: RandBoolReorderFilterObf()(f.Filter)}

		default:
			return filter
		}
	}
}

/*
	Casing Obfuscation Middlewares
*/

// TODO: Avoid attribute types that have specific formats and may break?
func RandCaseFilterObf(prob float32) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			switch v := f.(type) {
			case *parser.FilterEqualityMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterSubstring:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				for i := range v.Substrings {
					if v.Substrings[i].Initial != "" {
						v.Substrings[i].Initial = randomizeEachChar(v.Substrings[i].Initial, prob)
					}
					if v.Substrings[i].Any != "" {
						v.Substrings[i].Any = randomizeEachChar(v.Substrings[i].Any, prob)
					}
					if v.Substrings[i].Final != "" {
						v.Substrings[i].Final = randomizeEachChar(v.Substrings[i].Final, prob)
					}
				}
				return v
			case *parser.FilterGreaterOrEqual:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterLessOrEqual:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterApproxMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.AssertionValue = randomizeEachChar(v.AssertionValue, prob)
				return v
			case *parser.FilterPresent:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				return v
			case *parser.FilterExtensibleMatch:
				v.AttributeDesc = randomizeEachChar(v.AttributeDesc, prob)
				v.MatchValue = randomizeEachChar(v.MatchValue, prob)
				return v
			}
			return f
		},
	)
}

func randomizeEachChar(s string, prob float32) string {
	result := make([]rune, len(s))
	for i, char := range s {
		if rand.Float32() < prob {
			result[i] = unicode.ToUpper(char)
		} else {
			result[i] = unicode.ToLower(char)
		}
	}
	return string(result)
}

/*
	Value Obfuscation Middlewares
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

func RandPrependZerosFilterObf(maxZeros int) func(parser.Filter) parser.Filter {
	prependZerosFixed := func(attrName string, value string) string {
		tokenFormat, err := parser.GetAttributeTokenFormat(attrName)
		if err != nil {
			return value
		}

		if slices.Contains(parser.NumberFormats, tokenFormat) {
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
					sliceBefore, sliceAfter := SplitSlice(f.Substrings, subIdx)

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
					sliceBefore, sliceAfter := SplitSlice(f.Substrings, subIdx)

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
					sliceBefore, sliceAfter := SplitSlice(f.Substrings, subIdx)

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
