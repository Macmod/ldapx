package filtermid

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"

	"github.com/Macmod/ldapx/parser"
)

func LeafApplierFilterMiddleware(fm FilterMiddleware) FilterMiddleware {
	var applier FilterMiddleware
	applier = func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: applier(f.Filter)}

		default:
			return fm(filter)
		}
	}

	return applier
}

func HexEncodeChar(c rune) string {
	return fmt.Sprintf("\\%02x", c)
}

func RandomlyHexEncodeString(s string, prob float32) string {
	var result strings.Builder
	for _, c := range s {
		if rand.Float32() < prob {
			result.WriteString(HexEncodeChar(c))
		} else {
			result.WriteRune(c)
		}
	}

	return result.String()
}

func GetSomeRandChars(maxChars int) []rune {
	numChars := rand.Intn(maxChars)
	randomChars := make([]rune, numChars)

	for i := range randomChars {
		// ASCII printable characters range: 33-126
		randomChars[i] = rune(rand.Intn(94) + 33)
	}

	return randomChars
}

func ReplaceTimestamp(value string, prepend bool, append bool, maxChars int) string {
	re := regexp.MustCompile(`(\d{14})\.(\d*)Z$`) // TODO: What about leading zeros?
	return re.ReplaceAllStringFunc(value, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 3 {
			var prependStr string
			var appendStr string

			if prepend {
				prependStr = string(GetSomeRandChars(maxChars))
			}

			if append {
				appendStr = string(GetSomeRandChars(maxChars))
			}

			return fmt.Sprintf("%s.%s%sZ%s", parts[1], parts[2], prependStr, appendStr)
		}
		return match
	})
}

func PrependZeros(input string, maxZeros int) string {
	numZeros := rand.Intn(maxZeros)
	if len(input) > 0 && input[0] == '-' {
		zeros := strings.Repeat("0", numZeros)
		return "-" + zeros + input[1:]
	}

	return strings.Repeat("0", numZeros) + input
}

func AddRandSpacing(s string, maxSpaces int) string {
	var result strings.Builder
	var numSpaces int
	for _, char := range s {
		numSpaces = rand.Intn(maxSpaces)
		if numSpaces > 0 {
			result.WriteString(strings.Repeat(" ", numSpaces))
		}
		result.WriteRune(char)
	}

	numSpaces = rand.Intn(maxSpaces)
	if numSpaces > 0 {
		result.WriteString(strings.Repeat(" ", numSpaces))
	}

	return result.String()
}

func MapToOID(attrName string) (string, error) {
	oid, ok := parser.OidsMap[strings.ToLower(attrName)]

	if !ok {
		return attrName, fmt.Errorf("OID not found")
	}

	return oid, nil
}

func PrefixRandZerosToOID(oid string, maxZeros int) string {
	parts := strings.Split(oid, ".")
	var result []string

	for _, part := range parts {
		numZeros := rand.Intn(maxZeros + 1)
		result = append(result, PrependZeros(part, len(part)+numZeros))
	}

	return strings.Join(result, ".")
}
