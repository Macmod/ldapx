package basedn

import (
	"math/rand"
	"sort"
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
func OIDAttributeBaseDNObf(maxSpaces int, maxZeros int, includePrefix bool) func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				attrName := kv[0]
				if oid, exists := parser.OidsMap[strings.ToLower(attrName)]; exists {
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

				parts[i] = attrName + "=" + kv[1]
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
		if dn == "" || maxSpaces <= 0 {
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

// shouldReplaceBaseDN reports whether a BaseDN is eligible for replacement by
// an alternative DN form. An empty BaseDN is never replaced; when match is set,
// only the BaseDN it names is, which scopes the replacement to a single object
// instead of every request going through the proxy.
func shouldReplaceBaseDN(dn string, match string) bool {
	if dn == "" {
		return false
	}

	if match == "" {
		return true
	}

	return strings.EqualFold(dn, match)
}

// GUIDBaseDNObf replaces the BaseDN with the <GUID=hex> alternative form.
// Per MS-ADTS 3.1.1.3.1.2.4, AD supports <GUID=object_guid> where object_guid
// is the hex representation of the objectGUID attribute. This completely changes
// the BaseDN format, making it unrecognizable as a traditional DN.
//
// Since the GUID names a fixed object, the replacement also changes which
// object is being addressed. When match is set, only that BaseDN is replaced
// and every other one is forwarded unchanged.
func GUIDBaseDNObf(guidHex string, match string) func(string) string {
	return func(dn string) string {
		if guidHex == "" || !shouldReplaceBaseDN(dn, match) {
			return dn
		}
		return "<GUID=" + guidHex + ">"
	}
}

// SIDBaseDNObf replaces the BaseDN with the <SID=sid> alternative form.
// Per MS-ADTS 3.1.1.3.1.2.4, AD supports <SID=sid> where sid is either
// the string form (S-1-5-21-...) or hex representation of the binary SID.
//
// As with the GUID form, the replacement changes which object is addressed,
// and match scopes it to a single BaseDN.
func SIDBaseDNObf(sid string, match string) func(string) string {
	return func(dn string) string {
		if sid == "" || !shouldReplaceBaseDN(dn, match) {
			return dn
		}
		return "<SID=" + sid + ">"
	}
}

// wellKnownContainers maps the RDN prefix of a well-known container to the
// hexadecimal form of its well-known GUID (MS-ADTS 6.1.1.4). The prefixes are
// matched case-insensitively against the beginning of the BaseDN, and the
// remainder of the BaseDN is used as the object_DN of the WKGUID form.
var wellKnownContainers = map[string]string{
	"CN=Users,":                     "a9d1ca15768811d1aded00c04fd8d5cd",
	"CN=Computers,":                 "aa312825768811d1aded00c04fd8d5cd",
	"CN=System,":                    "ab1d30f3768811d1aded00c04fd8d5cd",
	"OU=Domain Controllers,":        "a361b2ffffd211d1aa4b00c04fd7d83a",
	"CN=LostAndFound,":              "ab8153b7768811d1aded00c04fd8d5cd",
	"CN=ForeignSecurityPrincipals,": "22b70c67d56e4efb91e9300fca3dc1aa",
	"CN=Program Data,":              "09460c08ae1e4a4ea0f64aee7daa1e5a",
	"CN=Microsoft,CN=Program Data,": "f4be92a4c777485e878e9421d53087db",
	"CN=NTDS Quotas,":               "6227f0af1fc2410d8e3bb10615bb5b0f",
	"CN=Infrastructure,":            "2fbac1870ade11d297c400c04fd8d5cd",
	"CN=Deleted Objects,":           "18e2ea80684f11d2b9aa00c04f79f805",
	"CN=Managed Service Accounts,":  "1eb93889e40c45df9f0c64d23bbb6237",
}

// WKGUIDFormatBaseDNObf converts the BaseDN of a well-known container into the
// `<WKGUID=guid,object_DN>` alternative DN form (MS-ADTS 3.1.1.3.1.2.4), where
// object_DN is the NC that holds the wellKnownObjects value.
//
// Both forms resolve to the same object, and BaseDNs that do not name a
// well-known container are left unchanged.
func WKGUIDFormatBaseDNObf() func(string) string {
	// Longest prefix first, so that nested containers such as
	// `CN=Microsoft,CN=Program Data,` win over their parent.
	prefixes := make([]string, 0, len(wellKnownContainers))
	for prefix := range wellKnownContainers {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	return func(dn string) string {
		for _, prefix := range prefixes {
			if len(dn) <= len(prefix) || !strings.EqualFold(dn[:len(prefix)], prefix) {
				continue
			}

			return "<WKGUID=" + wellKnownContainers[prefix] + "," + dn[len(prefix):] + ">"
		}

		return dn
	}
}

// RandHexValueBaseDNObf randomly hex encodes characters in BaseDN
func RandHexValueBaseDNObf(prob float64) func(string) string {
	return func(dn string) string {
		parts := strings.Split(dn, ",")
		for i, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				value := kv[1]
				startQuote := value[0] == '"'
				endQuote := value[len(value)-1] == '"'
				if startQuote || endQuote {
					continue
				}

				spaces := ""
				if strings.HasSuffix(value, " ") {
					valueWithoutSpaces := strings.TrimRight(value, " ")
					spaces = strings.Repeat(" ", len(value)-len(valueWithoutSpaces))
					value = valueWithoutSpaces
				}

				kv[1] = helpers.RandomlyHexEncodeString(value, prob) + spaces

				parts[i] = kv[0] + "=" + kv[1]
			}
		}
		return strings.Join(parts, ",")
	}
}

/*
	Alternative DN forms (MS-ADTS 3.1.1.3.1.2.4)

	`<GUID=object_guid>` and `<SID=sid>` name an object directly, while
	`<WKGUID=guid,object_DN>` also carries the DN of the NC holding the
	wellKnownObjects value that resolves the GUID.
*/

const wkGUIDPrefix = "<WKGUID="

// splitWKGUID breaks a `<WKGUID=guid,object_DN>` BaseDN into the GUID and the
// object_DN it wraps. The second return value reports whether dn is in that
// form at all.
func splitWKGUID(dn string) (guid string, objectDN string, ok bool) {
	if len(dn) <= len(wkGUIDPrefix) || !strings.EqualFold(dn[:len(wkGUIDPrefix)], wkGUIDPrefix) {
		return "", "", false
	}

	if !strings.HasSuffix(dn, ">") {
		return "", "", false
	}

	body := dn[len(wkGUIDPrefix) : len(dn)-1]

	// The GUID is a plain hexadecimal string, so the first comma of the body
	// always separates it from the object_DN, which may hold any number of
	// further commas.
	sep := strings.Index(body, ",")
	if sep == -1 {
		return "", "", false
	}

	return body[:sep], body[sep+1:], true
}

// applyToDNPart runs mid over the DN carried by an alternative DN form, leaving
// the form itself untouched, so that BaseDN middlewares keep composing after a
// form has been produced.
//
// The object_DN of `<WKGUID=guid,object_DN>` is a regular DN and is transformed
// in place; the GUID is never handed to the middleware. `<GUID=...>` and
// `<SID=...>` carry no DN and are passed through unchanged, since transforming
// them would only corrupt the reference.
func applyToDNPart(mid BaseDNMiddleware) BaseDNMiddleware {
	return func(dn string) string {
		if !strings.HasPrefix(dn, "<") {
			return mid(dn)
		}

		guid, objectDN, ok := splitWKGUID(dn)
		if !ok {
			return dn
		}

		return wkGUIDPrefix + guid + "," + mid(objectDN) + ">"
	}
}
