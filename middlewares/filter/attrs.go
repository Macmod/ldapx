package filtermid

import (
	"fmt"
	"math/rand"
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

func attemptMapToOID(attrName string) (string, error) {
	oid, ok := parser.OidsMap[strings.ToLower(attrName)]

	if !ok {
		return attrName, fmt.Errorf("OID not found")
	}

	return oid, nil
}

func prefixRandZerosToOID(oid string, maxZeros int) string {
	parts := strings.Split(oid, ".")
	var result []string

	for _, part := range parts {
		numZeros := rand.Intn(maxZeros + 1)
		result = append(result, prependZeros(part, len(part)+numZeros))
	}

	return strings.Join(result, ".")
}

func OIDAttributeFilterObf(maxZeros int, includePrefix bool) func(f parser.Filter) parser.Filter {
	obfuscate := func(attr string) string {
		oid, err := attemptMapToOID(attr)
		if err == nil {
			mapped := prefixRandZerosToOID(oid, maxZeros)
			if includePrefix {
				mapped = fmt.Sprintf("oID.%s", mapped)
			}

			return mapped
		}

		return attr
	}

	return func(f parser.Filter) parser.Filter {
		switch v := f.(type) {
		case *parser.FilterEqualityMatch:
			v.AttributeDesc = obfuscate(v.AttributeDesc)
		case *parser.FilterAnd:
			for i := range v.Filters {
				v.Filters[i] = OIDAttributeFilterObf(maxZeros, includePrefix)(v.Filters[i])
			}
		case *parser.FilterOr:
			for i := range v.Filters {
				v.Filters[i] = OIDAttributeFilterObf(maxZeros, includePrefix)(v.Filters[i])
			}
		case *parser.FilterNot:
			v.Filter = OIDAttributeFilterObf(maxZeros, includePrefix)(v.Filter)
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
	}
}
