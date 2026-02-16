package filter

import (
	"math/rand"
	"slices"
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/middlewares/helpers"
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

func OIDAttributeFilterObf(maxSpaces int, maxZeros int, includePrefix bool) func(f parser.Filter) parser.Filter {
	obfuscate := func(attr string) string {
		attrName := attr
		oid, err := MapToOID(attr)
		if err == nil {
			attrName = oid
		}

		if parser.IsOID(attrName) {
			if maxSpaces > 0 {
				attrName += strings.Repeat(" ", 1+rand.Intn(maxSpaces))
			}

			if maxZeros > 0 {
				attrName = helpers.RandomlyPrependZerosOID(attrName, maxZeros)
			}

			if !strings.HasPrefix(strings.ToLower(attrName), "oid.") {
				attrName = "oID." + attrName
			}
		}

		return attrName
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

func ANRSubstringGarbageFilterObf(maxChars int, garbageCharset string) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			if em, ok := f.(*parser.FilterEqualityMatch); ok {
				if em.AttributeDesc == "aNR" {
					numGarbage := 1 + rand.Intn(maxChars)
					garbage := helpers.GenerateGarbageString(numGarbage, garbageCharset)

					return &parser.FilterSubstring{
						AttributeDesc: "aNR",
						Substrings: []parser.SubstringFilter{
							{Initial: em.AssertionValue},
							{Final: garbage},
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
		return helpers.GenerateGarbageString(garbageSize, chars)
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

			if rand.Intn(2) == 0 {
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

func RandGarbageFilterObf(maxGarbage int, garbageSize int, charset string) func(parser.Filter) parser.Filter {
	var applier func(parser.Filter) parser.Filter

	applier = func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			// Recurse into AND children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			// Recurse into OR children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			// Important: Never recurse into NOT!
			// Treat entire NOT subtree as atomic to prevent UNDEFINED propagation.
			// Wrapping: OR(NOT(...), garbage) is safe; garbage inside NOT is not.
			numGarbage := 1 + rand.Intn(maxGarbage)
			garbageFilters := make([]parser.Filter, numGarbage+1)
			garbageFilters[0] = filter // Keep entire NOT intact
			for i := 1; i <= numGarbage; i++ {
				garbageFilters[i] = GenerateGarbageFilter("", garbageSize, charset)
			}
			return &parser.FilterOr{Filters: garbageFilters}

		default:
			// Leaf node - add garbage
			numGarbage := 1 + rand.Intn(maxGarbage)
			garbageFilters := make([]parser.Filter, numGarbage+1)
			garbageFilters[0] = filter
			for i := 1; i <= numGarbage; i++ {
				garbageFilters[i] = GenerateGarbageFilter("", garbageSize, charset)
			}
			return &parser.FilterOr{Filters: garbageFilters}
		}
	}

	return applier
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
			} else {
				return filter
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
			} else {
				return filter
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

func BitwiseDecomposeFilterObf(maxBits int) func(parser.Filter) parser.Filter {
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
/*
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
*/

/*
	Boolean Obfuscation Middlewares
*/

func RandAddBoolFilterObf(maxDepth int, prob float64) func(f parser.Filter) parser.Filter {
	return func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float64() < prob {
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

func RandDblNegBoolFilterObf(maxDepth int, prob float64) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float64() < prob {
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

func DeMorganBoolFilterObf() func(f parser.Filter) parser.Filter {
	var applyDeMorgan func(f parser.Filter) parser.Filter
	applyDeMorgan = func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			// Convert AND to OR using DeMorgan: a & b = !((!a) | (!b))
			notFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				notFilters[i] = &parser.FilterNot{Filter: applyDeMorgan(subFilter)}
			}
			return &parser.FilterNot{Filter: &parser.FilterOr{Filters: notFilters}}

		case *parser.FilterOr:
			// Convert OR to AND using DeMorgan: a | b = !((!a) & (!b))
			notFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				notFilters[i] = &parser.FilterNot{Filter: applyDeMorgan(subFilter)}
			}
			return &parser.FilterNot{Filter: &parser.FilterAnd{Filters: notFilters}}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: applyDeMorgan(f.Filter)}

		default:
			return filter
		}
	}

	return applyDeMorgan
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

func RandCaseFilterObf(prob float64) func(f parser.Filter) parser.Filter {
	obfuscate := func(attr string, val string, prob float64) (string, string) {
		tokenType, _ := parser.GetAttributeTokenFormat(attr)

		if tokenType == parser.TokenSID && !strings.HasPrefix(val, "S-") {
			return attr, val
		}

		obfAttr := helpers.RandomlyChangeCaseString(attr, prob)
		obfVal := helpers.RandomlyChangeCaseString(val, prob)

		return obfAttr, obfVal
	}

	return LeafApplierFilterMiddleware(
		func(f parser.Filter) parser.Filter {
			switch v := f.(type) {
			case *parser.FilterEqualityMatch:
				v.AttributeDesc, v.AssertionValue = obfuscate(v.AttributeDesc, v.AssertionValue, prob)
				return v
			case *parser.FilterSubstring:
				v.AttributeDesc = helpers.RandomlyChangeCaseString(v.AttributeDesc, prob)
				for i := range v.Substrings {
					if v.Substrings[i].Initial != "" {
						v.Substrings[i].Initial = helpers.RandomlyChangeCaseString(v.Substrings[i].Initial, prob)
					}
					if v.Substrings[i].Any != "" {
						v.Substrings[i].Any = helpers.RandomlyChangeCaseString(v.Substrings[i].Any, prob)
					}
					if v.Substrings[i].Final != "" {
						v.Substrings[i].Final = helpers.RandomlyChangeCaseString(v.Substrings[i].Final, prob)
					}
				}
				return v
			case *parser.FilterGreaterOrEqual:
				v.AttributeDesc, v.AssertionValue = obfuscate(v.AttributeDesc, v.AssertionValue, prob)
				return v
			case *parser.FilterLessOrEqual:
				v.AttributeDesc, v.AssertionValue = obfuscate(v.AttributeDesc, v.AssertionValue, prob)
				return v
			case *parser.FilterApproxMatch:
				v.AttributeDesc, v.AssertionValue = obfuscate(v.AttributeDesc, v.AssertionValue, prob)
				return v
			case *parser.FilterPresent:
				v.AttributeDesc, _ = obfuscate(v.AttributeDesc, "S-", prob)
				return v
			case *parser.FilterExtensibleMatch:
				v.AttributeDesc, v.MatchValue = obfuscate(v.AttributeDesc, v.MatchValue, prob)
				return v
			}
			return f
		},
	)
}

/*
	Value Obfuscation Middlewares
*/

func EqualityToApproxMatchFilterObf() FilterMiddleware {
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

func RandHexValueFilterObf(prob float64) func(parser.Filter) parser.Filter {
	applyHexEncoding := func(attr string, value string) string {
		tokenFormat, err := parser.GetAttributeTokenFormat(attr)
		if err == nil && tokenFormat == parser.TokenDNString {
			return RandomlyHexEncodeDNString(value, prob)
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

			case *parser.FilterApproxMatch:
				return &parser.FilterApproxMatch{
					AttributeDesc:  f.AttributeDesc,
					AssertionValue: applyHexEncoding(f.AttributeDesc, f.AssertionValue),
				}

			default:
				return filter
			}
		},
	)

	return applier
}

func RandTimestampSuffixFilterObf(maxChars int, charset string, useComma bool) func(parser.Filter) parser.Filter {
	replaceTimestampFixed := func(value string) string {
		return ReplaceTimestamp(value, maxChars, charset, useComma)
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

func RandSubstringSplitFilterObf(prob float64) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterEqualityMatch:
			if rand.Float64() < prob {
				// Only apply to string attributes
				tokenType, err := parser.GetAttributeTokenFormat(f.AttributeDesc)
				if err == nil && tokenType == parser.TokenStringUnicode {
					chars := []rune(f.AssertionValue)
					splitPoint := rand.Intn(len(chars) + 1)
					substrings := []parser.SubstringFilter{}

					if splitPoint > 0 {
						substrings = append(substrings, parser.SubstringFilter{
							Initial: string(chars[:splitPoint]),
						})
					}

					if splitPoint < len(chars) {
						substrings = append(substrings, parser.SubstringFilter{
							Final: string(chars[splitPoint:]),
						})
					}

					return &parser.FilterSubstring{
						AttributeDesc: f.AttributeDesc,
						Substrings:    substrings,
					}
				}
			}
			return f

		case *parser.FilterSubstring:
			if rand.Float64() < prob && len(f.Substrings) > 0 {
				// Pick a random substring and split it
				subIdx := rand.Intn(len(f.Substrings))
				sub := f.Substrings[subIdx]

				if sub.Initial != "" {
					// Grab a suffix and put it in the next Any
					sliceBefore, sliceAfter := SplitSlice(f.Substrings, subIdx)

					splitPoint := rand.Intn(len(sub.Initial))
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

func generateTypo(attr string) string {
	runes := []rune(attr)

	index := rand.Intn(len(runes))

	var typoRune rune
	if rand.Intn(2) == 0 {
		typoRune = rune(rand.Intn(26) + 'a')
	} else {
		typoRune = rune(rand.Intn(26) + 'A')
	}

	runes[index] = typoRune

	return string(runes)
}

func EqualityToExtensibleFilterObf(dn bool) func(parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterEqualityMatch:
			return &parser.FilterExtensibleMatch{
				MatchingRule:  "",
				AttributeDesc: f.AttributeDesc,
				MatchValue:    f.AssertionValue,
				DNAttributes:  dn,
			}
		}

		return filter
	})
}

func ReplaceTautologiesFilterObf() func(parser.Filter) parser.Filter {
	greedyAttrPresences := []string{
		// The 4 first are explicitly mentioned in MS-ADTS section 3.1.1.3.1.3.1 (Search Filters)
		"objectclass", "distinguishedname", "name", "objectguid",
		"objectcategory", "whencreated", "whenchanged", "usncreated", "usnchanged",
	}

	existingAttrs := make([]string, 0, len(parser.AttrContexts))
	for attr := range parser.AttrContexts {
		existingAttrs = append(existingAttrs, attr)
	}

	// For any filter, the basic tautology [should] be true
	makeBasicTautology := func(filter parser.Filter) parser.Filter {
		return &parser.FilterOr{
			Filters: []parser.Filter{
				&parser.FilterNot{Filter: filter},
				filter,
			},
		}
	}

	// MS-ADTS implies that 0 & 0 is always true :-)
	randomBitwiseTautologyAnd := func(parser.Filter) parser.Filter {
		randomAttr := parser.BitwiseAttrs[rand.Intn(len(parser.BitwiseAttrs))]

		return &parser.FilterOr{
			Filters: []parser.Filter{
				&parser.FilterExtensibleMatch{
					MatchingRule:  "1.2.840.113556.1.4.803",
					AttributeDesc: randomAttr,
					MatchValue:    "0",
				},
				&parser.FilterNot{
					Filter: &parser.FilterPresent{
						AttributeDesc: randomAttr,
					},
				},
			},
		}
	}

	// OR with 2**32-1
	randomBitwiseTautologyOr := func(parser.Filter) parser.Filter {
		randomAttr := parser.BitwiseAttrs[rand.Intn(len(parser.BitwiseAttrs))]

		return &parser.FilterOr{
			Filters: []parser.Filter{
				&parser.FilterExtensibleMatch{
					MatchingRule:  "1.2.840.113556.1.4.804",
					AttributeDesc: randomAttr,
					MatchValue:    "4294967295",
				},
				&parser.FilterNot{
					Filter: &parser.FilterPresent{
						AttributeDesc: randomAttr,
					},
				},
				&parser.FilterEqualityMatch{
					AttributeDesc:  randomAttr,
					AssertionValue: "0",
				},
			},
		}
	}

	randomTypoTautology := func(parser.Filter) parser.Filter {
		var typoAttr string
		for {
			// Get a random existing attribute
			randomAttr := existingAttrs[rand.Intn(len(existingAttrs))]

			// Generate a typo of the random attribute
			typoAttr = generateTypo(randomAttr)

			// Check if the typo matches an existing attribute
			if slices.Contains(existingAttrs, strings.ToLower(typoAttr)) {
				continue
			}

			return &parser.FilterNot{
				Filter: &parser.FilterPresent{
					AttributeDesc: typoAttr,
				},
			}
		}
	}

	randomPresenceBasicTautology := func(filter parser.Filter) parser.Filter {
		var randomAttr string
		currentAttr, _ := parser.GetAttrName(filter)
		for randomAttr == "" || randomAttr == currentAttr {
			randomAttr = existingAttrs[rand.Intn(len(existingAttrs))]
		}

		return makeBasicTautology(
			&parser.FilterPresent{
				AttributeDesc: randomAttr,
			},
		)
	}

	randomEqualityBasicTautology := func(filter parser.Filter) parser.Filter {
		var randomAttr string
		currentAttr, _ := parser.GetAttrName(filter)
		for randomAttr == "" || randomAttr == currentAttr {
			randomAttr = existingAttrs[rand.Intn(len(existingAttrs))]
		}

		return makeBasicTautology(
			&parser.FilterEqualityMatch{
				AttributeDesc:  randomAttr,
				AssertionValue: string(rand.Intn(26) + 'a'),
			},
		)
	}

	randomSubstringBasicTautology := func(filter parser.Filter) parser.Filter {
		var randomAttr string
		currentAttr, _ := parser.GetAttrName(filter)
		for randomAttr == "" || randomAttr == currentAttr {
			randomAttr = existingAttrs[rand.Intn(len(existingAttrs))]
		}

		substrings := []parser.SubstringFilter{}
		if rand.Intn(2) == 0 {
			substrings = append(substrings, parser.SubstringFilter{Initial: string(rand.Intn(26) + 'a')})
		}
		if rand.Intn(2) == 0 {
			substrings = append(substrings, parser.SubstringFilter{Any: string(rand.Intn(26) + 'a')})
		}
		if rand.Intn(2) == 0 {
			substrings = append(substrings, parser.SubstringFilter{Final: string(rand.Intn(26) + 'a')})
		}

		return makeBasicTautology(
			&parser.FilterSubstring{
				AttributeDesc: randomAttr,
				Substrings:    substrings,
			},
		)
	}

	randomBitwiseBasicTautology := func(filter parser.Filter) parser.Filter {
		randomAttr := parser.BitwiseAttrs[rand.Intn(len(parser.BitwiseAttrs))]

		var matchingRule string
		kind := rand.Intn(2)
		if kind == 0 {
			matchingRule = "1.2.840.113556.1.4.804"
		} else {
			matchingRule = "1.2.840.113556.1.4.803"
		}

		return makeBasicTautology(
			&parser.FilterExtensibleMatch{
				MatchingRule:  matchingRule,
				AttributeDesc: randomAttr,
				MatchValue:    strconv.Itoa(rand.Intn(4294967296)),
			},
		)
	}

	tautologies := []func(parser.Filter) parser.Filter{
		randomBitwiseTautologyAnd,
		randomBitwiseTautologyOr,
		randomTypoTautology,
		randomPresenceBasicTautology,
		randomEqualityBasicTautology,
		randomSubstringBasicTautology,
		randomBitwiseBasicTautology,
	}

	return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterPresent:
			if slices.Contains(greedyAttrPresences, strings.ToLower(f.AttributeDesc)) {
				return tautologies[rand.Intn(len(tautologies))](f)
			}
		}

		return filter
	})
}
