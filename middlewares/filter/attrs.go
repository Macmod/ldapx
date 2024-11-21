package filtermid

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"

	"github.com/Macmod/ldapx/parser"
)

/*
	AttributeName FilterMiddlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func OIDAttributeFilterObf(maxZeros int, includePrefix bool) func(f parser.Filter) parser.Filter {
	obfuscate := func(attr string) string {
		oid, err := MapToOID(attr)
		if err == nil {
			mapped := PrefixRandZerosToOID(oid, maxZeros)
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
