package filter

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/middlewares/helpers"
	"github.com/Macmod/ldapx/parser"
)

// LeafApplierFilterMiddleware applies a FilterMiddleware to all leaf nodes of a filter tree
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

// Miscellaneous helper functions
func SplitSlice[T any](slice []T, idx int) ([]T, []T) {
	before := make([]T, idx)
	after := make([]T, len(slice)-idx-1)

	copy(before, slice[:idx])
	copy(after, slice[idx+1:])

	return before, after
}

func RandomlyHexEncodeDNString(dnString string, prob float64) string {
	parts := strings.Split(dnString, ",")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			value := kv[1]
			encodedValue := helpers.RandomlyHexEncodeString(value, prob)
			parts[i] = kv[0] + "=" + encodedValue
		}
	}
	return strings.Join(parts, ",")
}

func ReplaceTimestamp(value string, maxChars int, charset string) string {
	re := regexp.MustCompile(`^([0-9]{14})([.,].*)Z(.*)`)
	return re.ReplaceAllStringFunc(value, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 4 {
			var prependStr string
			var appendStr string

			randStr1 := helpers.GenerateGarbageString(maxChars, charset)
			randStr2 := helpers.GenerateGarbageString(maxChars, charset)
			randVal := rand.Intn(3)
			if randVal == 0 {
				prependStr = randStr1
			} else if randVal == 1 {
				appendStr = randStr2
			} else {
				prependStr = randStr1
				appendStr = randStr2
			}

			return fmt.Sprintf("%s%s%sZ%s%s", parts[1], parts[2], prependStr, appendStr, parts[3])
		}
		return match
	})
}

// Prepend Zeros functions
func PrependZerosToSID(sid string, maxZeros int) string {
	parts := strings.Split(sid, "-")
	for i := range parts {
		if i == 0 {
			continue
		}

		for j, c := range parts[i] {
			if c >= '0' && c <= '9' {
				prefix := parts[i][:j]
				suffix := parts[i][j:]
				numZeros := rand.Intn(maxZeros)
				zerosStr := strings.Repeat("0", numZeros)
				parts[i] = prefix + zerosStr + suffix
				break
			}
		}
	}
	return strings.Join(parts, "-")
}

func PrependZerosToNumber(input string, maxZeros int) string {
	numZeros := rand.Intn(maxZeros)
	zerosStr := strings.Repeat("0", numZeros)
	if len(input) > 0 && input[0] == '-' {
		return "-" + zerosStr + input[1:]
	}
	return zerosStr + input
}

func PrependZerosToOID(oid string, maxZeros int) string {
	parts := strings.Split(oid, ".")
	var result []string

	for _, part := range parts {
		numZeros := rand.Intn(maxZeros + 1)
		result = append(result, PrependZerosToNumber(part, len(part)+numZeros))
	}

	return strings.Join(result, ".")
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

// TODO: Review both methods' logic of randomness
func AddANRSpacing(value string, maxSpaces int) string {
	spacesFst := strings.Repeat(" ", 1+rand.Intn(maxSpaces))
	spacesEqSign := strings.Repeat(" ", 1+rand.Intn(maxSpaces))
	spacesLst := strings.Repeat(" ", 1+rand.Intn(maxSpaces))
	if strings.HasPrefix(strings.TrimSpace(value), "=") {
		// If there's an equal sign prefix, we must consider adding spaces right after it too
		idx := strings.Index(value, "=")

		if idx != -1 && idx+1 < len(value) && rand.Float64() < 0.5 {
			value = value[:idx+1] + spacesEqSign + value[idx+1:]
		}
	}

	if rand.Float64() < 0.5 {
		return spacesFst + value
	} else if rand.Float64() < 0.5 {
		return value + spacesLst
	} else {
		return spacesFst + value + spacesLst
	}
}

func AddDNSpacing(value string, maxSpaces int) string {
	parts := strings.Split(value, ",")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			switch rand.Intn(4) {
			case 0:
				kv[0] = kv[0] + strings.Repeat(" ", 1+rand.Intn(maxSpaces))
			case 1:
				kv[1] = strings.Repeat(" ", 1+rand.Intn(maxSpaces)) + kv[1]
			case 2:
				kv[0] = strings.Repeat(" ", 1+rand.Intn(maxSpaces)) + kv[0]
			case 3:
				kv[1] = kv[1] + strings.Repeat(" ", 1+rand.Intn(maxSpaces))
			}
			parts[i] = strings.Join(kv, "=")
		}
	}
	return strings.Join(parts, ",")
}

func AddSIDSpacing(sid string, maxSpaces int) string {
	parts := strings.Split(sid, "-")
	if len(parts) >= 3 {
		// Add spaces before revision number (parts[1])
		spaces := strings.Repeat(" ", rand.Intn(maxSpaces+1))
		parts[1] = spaces + parts[1]

		// Add spaces before subauthority count (parts[2])
		spaces = strings.Repeat(" ", rand.Intn(maxSpaces+1))
		parts[2] = spaces + parts[2]
	}
	return strings.Join(parts, "-")
}

// Comparison helpers

const CharOrdering = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// TODO: Review
func GetNextString(s string) string {
	// Convert string to rune slice for easier manipulation
	chars := []rune(s)

	// Start from rightmost character
	for i := len(chars) - 1; i >= 0; i-- {
		// Find current char position in CharOrdering
		pos := strings.IndexRune(CharOrdering, chars[i])

		// If not last char in CharOrdering, increment to next
		if pos < len(CharOrdering)-1 {
			chars[i] = rune(CharOrdering[pos+1])
			return string(chars)
		}

		// If last char in CharOrdering, set to first char and continue left
		chars[i] = rune(CharOrdering[0])
	}

	// If all chars were last in CharOrdering, append first char
	return s + string(CharOrdering[0])
}

func GetPreviousString(s string) string {
	chars := []rune(s)

	for i := len(chars) - 1; i >= 0; i-- {
		pos := strings.IndexRune(CharOrdering, chars[i])

		if pos > 0 {
			chars[i] = rune(CharOrdering[pos-1])
			return string(chars)
		}

		chars[i] = rune(CharOrdering[len(CharOrdering)-1])
	}

	// If string is all first chars, remove first char
	if len(s) > 1 {
		return s[:len(s)-1]
	}

	return s
}

func GetNextSID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 1 {
		return sid
	}

	if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
		parts[len(parts)-1] = strconv.Itoa(num + 1)
	}
	return strings.Join(parts, "-")
}

func GetPreviousSID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 1 {
		return sid
	}

	if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil && num > 0 {
		parts[len(parts)-1] = strconv.Itoa(num - 1)
	}
	return strings.Join(parts, "-")
}
