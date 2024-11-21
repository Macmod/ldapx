package parser

import "regexp"

// IsOID checks if a string matches OID pattern (numbers separated by dots)
func IsOID(s string) bool {
	oidPattern := regexp.MustCompile(`^(?i:oid\.)?\d+(\.\d+)*$`)
	return oidPattern.MatchString(s)
}
