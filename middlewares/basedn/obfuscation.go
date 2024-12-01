package basedn

import (
	"fmt"
	"math/rand"
	"strings"

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
func RandCaseBaseDNObf(prob float32) func(string) string {
	return func(dn string) string {
		var builder strings.Builder
		for _, c := range dn {
			if rand.Float32() < prob {
				builder.WriteString(strings.ToUpper(string(c)))
			} else {
				builder.WriteString(strings.ToLower(string(c)))
			}
		}
		return builder.String()
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
func OIDPrependZerosBaseDNObf(minZeros int, maxZeros int) func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && parser.IsOID(kv[0]) {
				oidParts := strings.Split(kv[0], ".")
				for j, num := range oidParts {
					zeros := strings.Repeat("0", minZeros+rand.Intn(maxZeros-minZeros+1))
					oidParts[j] = zeros + num
				}
				parts[i] = strings.Join(oidParts, ".") + "=" + kv[1]
			}
		}
		return strings.Join(parts, ",")
	}
}

// RandSpacingBaseDNObf adds random spacing to BaseDN in either the beginning or end
func RandSpacingBaseDNObf(minSpaces int, maxSpaces int, probEnd float32) func(string) string {
	return func(dn string) string {
		if dn == "" {
			return dn
		}
		spaces := strings.Repeat(" ", minSpaces+rand.Intn(maxSpaces-minSpaces+1))
		if rand.Float32() < probEnd {
			return dn + spaces
		}
		return spaces + dn
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
func RandHexValueBaseDNObf(prob float32) func(string) string {
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

				for _, c := range value {
					if rand.Float32() < prob {
						builder.WriteString(fmt.Sprintf("\\%02x", c))
					} else {
						builder.WriteRune(c)
					}
				}
				kv[1] = builder.String()
				parts[i] = kv[0] + "=" + kv[1]
			}
		}
		return strings.Join(parts, ",")
	}
}
