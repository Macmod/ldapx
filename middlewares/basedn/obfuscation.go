package basedn

import (
	"math/rand"
	"strings"

	"github.com/Macmod/ldapx/middlewares/helpers"
	"github.com/Macmod/ldapx/parser"
)

/*
	Obfuscation BaseDN Middlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

// RandCaseBaseDNObf randomly changes case of BaseDN components
func RandCaseBaseDNObf(prob float64) func(string) string {
	return func(dn string) string {
		return helpers.RandomlyChangeCaseString(dn, prob)
	}
}

// OIDAttributeBaseDNObf converts attribute names in BaseDN to their OID form
func OIDAttributeBaseDNObf() func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				if oid, exists := parser.OidsMap[strings.ToLower(kv[0])]; exists {
					parts[i] = oid + "=" + kv[1]
				}
			}
		}
		return strings.Join(parts, ",")
	}
}

// Prepends zeros to attribute OIDs in BaseDN
func OIDPrependZerosBaseDNObf(maxZeros int) func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && parser.IsOID(kv[0]) {
				oidParts := strings.Split(kv[0], ".")
				for j, num := range oidParts {
					zeros := strings.Repeat("0", 1+rand.Intn(maxZeros))
					oidParts[j] = zeros + num
				}
				parts[i] = strings.Join(oidParts, ".") + "=" + kv[1]
			}
		}
		return strings.Join(parts, ",")
	}
}

// RandSpacingBaseDNObf adds random spacing to BaseDN in either the beginning or end
func RandSpacingBaseDNObf(maxSpaces int) func(string) string {
	return func(dn string) string {
		if dn == "" {
			return dn
		}

		var newDN string

		spaces1 := strings.Repeat(" ", 1+rand.Intn(maxSpaces))
		spaces2 := strings.Repeat(" ", 1+rand.Intn(maxSpaces))

		randVal := rand.Intn(3)
		if randVal == 0 {
			newDN = dn + spaces1
		} else if randVal == 1 {
			newDN = spaces1 + dn
		} else {
			newDN = spaces1 + dn + spaces2
		}

		return newDN
	}
}

// DoubleQuotesBaseDNObf adds double quotes around BaseDN components
func DoubleQuotesBaseDNObf() func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				value := kv[1]
				if strings.ContainsAny(value, "\\") {
					continue
				}

				if i == len(parts)-1 && strings.HasSuffix(value, " ") {
					trimmedValue := strings.TrimRight(value, " ")
					parts[i] = kv[0] + "=\"" + trimmedValue + "\"" + strings.Repeat(" ", len(value)-len(trimmedValue))
				} else {
					parts[i] = kv[0] + "=\"" + value + "\""
				}
			}
		}
		return strings.Join(parts, ",")
	}
}

// RandHexValueBaseDNObf randomly hex encodes characters in BaseDN
func RandHexValueBaseDNObf(prob float64) func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				var builder strings.Builder
				value := kv[1]
				startQuote := value[0] == '"'
				endQuote := value[len(value)-1] == '"'
				if startQuote || endQuote {
					builder.WriteString(value)
					continue
				}

				kv[1] = helpers.RandomlyHexEncodeString(value, prob)
				parts[i] = kv[0] + "=" + kv[1]
			}
		}
		return strings.Join(parts, ",")
	}
}
