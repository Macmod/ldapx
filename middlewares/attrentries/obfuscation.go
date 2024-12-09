package attrentries

import (
	"math/rand"
	"strings"

	"github.com/Macmod/ldapx/middlewares/helpers"
	"github.com/Macmod/ldapx/parser"
)

/*
	Obfuscation AttrEntries Middlewares

	References:
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func RandCaseAttrEntriesObf(prob float64) AttrEntriesMiddleware {
	return func(entries parser.AttrEntries) parser.AttrEntries {
		result := make(parser.AttrEntries, len(entries))

		for i, attr := range entries {
			result[i] = parser.Attribute{
				Name:   helpers.RandomlyChangeCaseString(attr.Name, prob),
				Values: attr.Values,
			}
		}
		return result
	}
}

func OIDAttributeAttrEntriesObf(maxSpaces int, maxZeros int, includePrefix bool) AttrEntriesMiddleware {
	return func(entries parser.AttrEntries) parser.AttrEntries {
		result := make(parser.AttrEntries, len(entries))

		for i, attr := range entries {
			name := attr.Name
			if oid, exists := parser.OidsMap[strings.ToLower(name)]; exists {
				name = oid
			}

			if parser.IsOID(name) {
				if maxSpaces > 0 {
					name += strings.Repeat(" ", 1+rand.Intn(maxSpaces))
				}

				if maxZeros > 0 {
					name = helpers.RandomlyPrependZerosOID(name, maxZeros)
				}

				if !strings.HasPrefix(strings.ToLower(name), "oid.") {
					name = "oID." + name
				}
			}

			result[i] = parser.Attribute{
				Name:   name,
				Values: attr.Values,
			}
		}
		return result
	}
}

func ReorderListAttrEntriesObf() AttrEntriesMiddleware {
	return func(entries parser.AttrEntries) parser.AttrEntries {
		result := make(parser.AttrEntries, len(entries))
		copy(result, entries)

		rand.Shuffle(len(result), func(i, j int) {
			result[i], result[j] = result[j], result[i]
		})

		return result
	}
}

// Ideas to be considered:
//   - Obfuscate the values of the attributes themselves (numeric, DN, SID, etc?)
//   - Add allowed attributes for that object type that aren't already specified,
//     but with random garbage that doesn't affect the object
