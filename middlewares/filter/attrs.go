package filtermid

import (
	"fmt"

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
