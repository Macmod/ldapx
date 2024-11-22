package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// IsOID checks if a string matches OID pattern (numbers separated by dots)
func IsOID(s string) bool {
	oidPattern := regexp.MustCompile(`^(?i:oid\.)?\d+(\.\d+)*$`)
	return oidPattern.MatchString(s)
}

// Gets the token format for an attribute
func GetAttributeTokenFormat(attributeName string) (LDAPTokenFormat, error) {
	if context, exists := AttrContexts[strings.ToLower(attributeName)]; exists {
		return context.Format, nil
	}

	return TokenStringUnicode, fmt.Errorf("Error: attribute format not found for attribute '%s'", attributeName)
}
