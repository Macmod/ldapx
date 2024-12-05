package attrlist

import (
	"math/rand"
	"slices"
	"strings"

	"github.com/Macmod/ldapx/middlewares/helpers"
	"github.com/Macmod/ldapx/parser"
)

/*
	Obfuscation AttrList Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

// RandCaseAttrListObf randomly changes case of attribute names
func RandCaseAttrListObf(prob float64) func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, len(attrs))

		for i, attr := range attrs {
			result[i] = helpers.RandomlyChangeCaseString(attr, prob)
		}
		return result
	}
}

// OIDAttributeAttrListObf converts attributes to their OID form
func OIDAttributeAttrListObf() func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, len(attrs))
		for i, attr := range attrs {
			if oid, exists := parser.OidsMap[strings.ToLower(attr)]; exists {
				result[i] = oid
			} else {
				result[i] = attr
			}
		}
		return result
	}
}

// RandOIDSpacingAttrListObf adds random spacing to the end of attributes in OID syntax
func RandOIDSpacingAttrListObf(maxSpaces int) func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, len(attrs))

		for i, attr := range attrs {
			if parser.IsOID(attr) {
				result[i] = attr + strings.Repeat(" ", rand.Intn(maxSpaces))
			} else {
				result[i] = attr
			}
		}
		return result
	}
}

// DuplicateAttrListObf duplicates random attributes
func DuplicateAttrListObf(prob float64) func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, 0)

		for _, attr := range attrs {
			duplicates := 1
			if rand.Float64() < prob {
				duplicates++
			}

			for i := 0; i < duplicates; i++ {
				result = append(result, attr)
			}
		}

		return result
	}
}

// GarbageExistingAttrListObf adds garbage to existing attributes
func GarbageExistingAttrListObf(maxGarbage int) func([]string) []string {
	return func(attrs []string) []string {
		if len(attrs) == 0 {
			return attrs
		}

		result := make([]string, len(attrs))
		copy(result, attrs)

		// Get all attribute names from parser.AttrContexts
		existingAttrs := make([]string, 0, len(parser.AttrContexts))
		for attr := range parser.AttrContexts {
			existingAttrs = append(existingAttrs, attr)
		}

		garbageCount := 1 + rand.Intn(maxGarbage)
		for i := 0; i < garbageCount; i++ {
			randomAttr := existingAttrs[rand.Intn(len(existingAttrs))]
			result = append(result, randomAttr)
		}
		return result
	}
}

// GarbageNonExistingAttrListObf adds completely new garbage attributes
func GarbageNonExistingAttrListObf(maxGarbage int, garbageSize int, garbageCharset string) func([]string) []string {
	return func(attrs []string) []string {
		if len(attrs) == 0 {
			return attrs
		}

		result := make([]string, len(attrs))
		copy(result, attrs)

		garbageCount := 1 + rand.Intn(maxGarbage)
		for i := 0; i < garbageCount; i++ {
			var garbage string
			exists := true
			for exists {
				garbage = helpers.GenerateGarbageString(garbageSize, garbageCharset)
				_, exists = parser.OidsMap[strings.ToLower(garbage)]
			}
			result = append(result, garbage)
		}
		return result
	}
}

// AddWildcardAttrListObf adds wildcards to the attributes list
func AddWildcardAttrListObf() func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, len(attrs))
		copy(result, attrs)
		result = append(result, "*")
		return result
	}
}

func ReplaceWithWildcardAttrListObf() func([]string) []string {
	return func(attrs []string) []string {
		newAttrs := []string{"*"}
		for _, attr := range attrs {
			if attr == "+" {
				newAttrs = append(newAttrs, "+")
			} else if slices.Contains(parser.RootDSEOperationalAttrs, strings.ToLower(attr)) ||
				slices.Contains(parser.RFCOperationalAttrs, strings.ToLower(attr)) {
				newAttrs = append(newAttrs, attr)
			}
		}

		return newAttrs
	}
}

func ReplaceWithEmptyAttrListObf() func([]string) []string {
	return func(attrs []string) []string {
		newAttrs := []string{}

		for _, attr := range attrs {
			if attr == "+" {
				newAttrs = append(newAttrs, "+")
			} else if slices.Contains(parser.RootDSEOperationalAttrs, strings.ToLower(attr)) ||
				slices.Contains(parser.RFCOperationalAttrs, strings.ToLower(attr)) {
				newAttrs = append(newAttrs, attr)
			}
		}

		if len(newAttrs) > 0 {
			newAttrs = append([]string{"*"}, newAttrs...)
		}

		return newAttrs
	}
}

func ReorderListAttrListObf() func([]string) []string {
	return func(attrs []string) []string {
		result := make([]string, len(attrs))
		copy(result, attrs)
		rand.Shuffle(len(result), func(i, j int) {
			result[i], result[j] = result[j], result[i]
		})
		return result
	}
}
