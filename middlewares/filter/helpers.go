package filter

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

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

func ReplaceTimestamp(value string, maxChars int, charset string, useComma bool) string {
	re := regexp.MustCompile(`^([0-9]{14})[.,](.*)(Z|[+-].{4})(.*)`)
	return re.ReplaceAllStringFunc(value, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 5 {
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

			sep := "."
			if useComma {
				sep = ","
			}

			return fmt.Sprintf("%s%s%s%s%s%s%s", parts[1], sep, parts[2], prependStr, parts[3], appendStr, parts[4])
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
				numZeros := 1 + rand.Intn(maxZeros)
				zerosStr := strings.Repeat("0", numZeros)
				parts[i] = prefix + zerosStr + suffix
				break
			}
		}
	}
	return strings.Join(parts, "-")
}

func PrependZerosToNumber(input string, maxZeros int) string {
	numZeros := 1 + rand.Intn(maxZeros)
	zerosStr := strings.Repeat("0", numZeros)
	if len(input) > 0 && input[0] == '-' {
		return "-" + zerosStr + input[1:]
	}
	return zerosStr + input
}

// Active Directory deletes a large set of code points during LDAP string
// preparation ([RFC4518] "Map to nothing") before comparing String(Unicode)
// values, so inserting them into an assertion value is result-preserving. The
// three sets below were derived from Unicode 17.0 and verified against a live DC
// (each stripped at every position on multiple attributes). They are
// patch-dependent - this is the mechanism behind CVE-2026-25177 /
// CVE-2026-27912.

// ignorableRunes are the 288 stripped code points that are also
// Default_Ignorable_Code_Point: invisible on the wire (zero-width joiners, bidi
// controls, variation selectors, combining grapheme joiner, Mongolian FVS).
var ignorableRunes = expandRuneRanges([][2]rune{
	{0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C}, {0x180B, 0x180D},
	{0x180F, 0x180F}, {0x200C, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x2064},
	{0x2066, 0x206F}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF}, {0xE0100, 0xE01EF},
})

// combiningRunes are the other 640 stripped code points: combining marks
// (Mn/Mc/Me diacritics, keycaps, Indic/Arabic marks) plus a few non-default-
// ignorable Arabic/interlinear format marks. AD strips them for matching, but
// unlike ignorableRunes they RENDER - the value looks accented/garbled - so they
// are opt-in.
var combiningRunes = expandRuneRanges([][2]rune{
	{0x0300, 0x034E}, {0x0350, 0x0362}, {0x0483, 0x0487}, {0x0591, 0x05BD}, {0x05BF, 0x05BF},
	{0x05C1, 0x05C2}, {0x05C4, 0x05C5}, {0x05C7, 0x05C7}, {0x0602, 0x0602}, {0x0604, 0x0605},
	{0x0610, 0x061A}, {0x064B, 0x065F}, {0x0670, 0x0670}, {0x06D8, 0x06DC}, {0x06E1, 0x06E4},
	{0x06E7, 0x06E8}, {0x06EA, 0x06ED}, {0x0711, 0x0711}, {0x0730, 0x074A}, {0x07A6, 0x07B0},
	{0x07EB, 0x07F3}, {0x07FD, 0x07FD}, {0x0818, 0x0819}, {0x081C, 0x0823}, {0x0825, 0x0827},
	{0x0829, 0x082D}, {0x0859, 0x085B}, {0x0890, 0x0891}, {0x0897, 0x089F}, {0x08CA, 0x0900},
	{0x093C, 0x093C}, {0x0951, 0x0954}, {0x09BC, 0x09BC}, {0x09FE, 0x09FE}, {0x0A01, 0x0A02},
	{0x0A3C, 0x0A3C}, {0x0A70, 0x0A71}, {0x0ABC, 0x0ABC}, {0x0AFA, 0x0AFF}, {0x0B3C, 0x0B3C},
	{0x0B55, 0x0B55}, {0x0C00, 0x0C00}, {0x0C04, 0x0C04}, {0x0C3C, 0x0C3C}, {0x0C55, 0x0C56},
	{0x0C81, 0x0C81}, {0x0CBC, 0x0CBC}, {0x0CD5, 0x0CD6}, {0x0CF3, 0x0CF3}, {0x0D00, 0x0D01},
	{0x0D3B, 0x0D3C}, {0x0D81, 0x0D81}, {0x0E47, 0x0E4D}, {0x0EBA, 0x0EBA}, {0x0ECC, 0x0ECC},
	{0x0ECE, 0x0ECE}, {0x0F39, 0x0F39}, {0x0F71, 0x0F71}, {0x0F7F, 0x0F7F}, {0x0F84, 0x0F84},
	{0x0F8D, 0x0F8F}, {0x135D, 0x135F}, {0x1715, 0x1715}, {0x1A74, 0x1A7C}, {0x1A7F, 0x1A7F},
	{0x1AB0, 0x1ADD}, {0x1AE0, 0x1AEB}, {0x1B6B, 0x1B73}, {0x1BAB, 0x1BAD}, {0x1C37, 0x1C37},
	{0x1CF4, 0x1CF4}, {0x1CF7, 0x1CF9}, {0x1DC0, 0x1DD1}, {0x1DE7, 0x1DFF}, {0x20D0, 0x20F0},
	{0x2CEF, 0x2CF1}, {0x2D7F, 0x2D7F}, {0x302A, 0x302F}, {0x3099, 0x309A}, {0xA66F, 0xA66F},
	{0xA674, 0xA67D}, {0xA69E, 0xA69F}, {0xA6F0, 0xA6F1}, {0xA82C, 0xA82C}, {0xA8C5, 0xA8C5},
	{0xA8E0, 0xA8F1}, {0xA8FF, 0xA8FF}, {0xA92B, 0xA92D}, {0xA9E5, 0xA9E5}, {0xAA7C, 0xAA7D},
	{0xAAEB, 0xAAEF}, {0xAAF5, 0xAAF6}, {0xFB1E, 0xFB1E}, {0xFE20, 0xFE2F}, {0xFFF9, 0xFFFB},
})

// altSpaceRunes are the Unicode space code points, other than U+0020, that AD
// folds to a single SPACE during string preparation ([RFC4518]); replacing an
// existing space with one of them leaves String(Unicode) matching unchanged.
var altSpaceRunes = []rune{0x1680, 0x180E, 0x202F, 0x205F, 0x3000}

func expandRuneRanges(ranges [][2]rune) []rune {
	out := make([]rune, 0, 512)
	for _, r := range ranges {
		for c := r[0]; c <= r[1]; c++ {
			out = append(out, c)
		}
	}
	return out
}

// maxStrippableValueLen is the observed limit, in UTF-16 code units, up to which
// Active Directory strips ignorable code points from a String(Unicode) assertion
// value. Past it the inserted code points are no longer removed and the result
// set changes, so keeping the output within this budget preserves it, including
// when the middleware is chained.
const maxStrippableValueLen = 127

// insertRunes inserts a random rune from pool into s at each inter-rune gap with
// probability prob, without letting the value exceed maxStrippableValueLen UTF-16
// code units. When pool is result-preserving under AD's String(Unicode) matching,
// so is the output. The budget is measured in UTF-16 units (a variation selector
// costs two).
func insertRunes(s string, pool []rune, prob float64) string {
	if prob <= 0 || len(pool) == 0 {
		return s
	}

	budget := maxStrippableValueLen - len(utf16.Encode([]rune(s)))

	var result strings.Builder
	insert := func() {
		if budget <= 0 || rand.Float64() >= prob {
			return
		}
		r := pool[rand.Intn(len(pool))]
		if cost := utf16.RuneLen(r); cost >= 0 && cost <= budget {
			result.WriteRune(r)
			budget -= cost
		}
	}

	for _, char := range s {
		insert()
		result.WriteRune(char)
	}
	insert()

	return result.String()
}

// substituteSpaces replaces each ASCII space in s, with probability prob, by a
// random rune from pool. When pool is a set AD folds back to a space (see
// altSpaceRunes), the output is result-preserving under String(Unicode) matching.
func substituteSpaces(s string, pool []rune, prob float64) string {
	if prob <= 0 || len(pool) == 0 {
		return s
	}

	var result strings.Builder
	for _, char := range s {
		if char == ' ' && rand.Float64() < prob {
			result.WriteRune(pool[rand.Intn(len(pool))])
		} else {
			result.WriteRune(char)
		}
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

	randVal := rand.Intn(3)
	if randVal == 0 {
		return spacesFst + value
	} else if randVal == 1 {
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
