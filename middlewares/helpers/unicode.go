package helpers

import (
	"math/rand"
	"strings"
	"unicode/utf16"
)

// Unicode fold/strip primitives shared by the filter and basedn middlewares. The
// character tables they operate on live in fold_table.go.
//
// Active Directory compares String(Unicode) values through a Windows
// LCMapStringEx sort key ([MS-ADTS] section 3.1.1.2.2.4 / section 6.5,
// [MS-UCODEREF]) at LCID 0409. Two families of edit leave that comparison's
// result the same: inserting code points that carry no sort weight (they are
// dropped), and substituting a character with any code point that shares its sort
// key (they match identically).

// ignorableModeCategories maps each IgnorableUnicode mode category to its
// insertion pool. invisible and marks are the invisible / combining strippers;
// modlet, modsym, symbols, and punct are the visible strippers above.
var ignorableModeCategories = map[string][]rune{
	"invisible": IgnorableRunes,
	"marks":     CombiningRunes,
	"modlet":    ModifierLetterRunes,
	"modsym":    ModifierSymbolRunes,
	"symbols":   SymbolRunes,
	"punct":     PunctuationRunes,
}

// ignorableModeOrder is the canonical category order, used for "all" and to keep
// the built pool deterministic.
var ignorableModeOrder = []string{"invisible", "marks", "modlet", "modsym", "symbols", "punct"}

// IgnorableModeRunes returns the insertion pool for a comma-separated list of
// IgnorableUnicode categories (invisible, marks, modlet, modsym, symbols, punct);
// "all" or an empty string selects every category, unknown names contribute
// nothing. Every returned code point is stripped by AD during comparison, so
// inserting them preserves the result set.
func IgnorableModeRunes(mode string) []rune {
	tokens := map[string]bool{}
	for _, p := range strings.Split(mode, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			tokens[p] = true
		}
	}
	selectAll := len(tokens) == 0 || tokens["all"]

	seen := map[rune]bool{}
	var pool []rune
	for _, name := range ignorableModeOrder {
		if !selectAll && !tokens[name] {
			continue
		}
		for _, r := range ignorableModeCategories[name] {
			if !seen[r] {
				seen[r] = true
				pool = append(pool, r)
			}
		}
	}
	return pool
}

func ExpandRuneRanges(ranges [][2]rune) []rune {
	out := make([]rune, 0, 512)
	for _, r := range ranges {
		for c := r[0]; c <= r[1]; c++ {
			out = append(out, c)
		}
	}
	return out
}

// MaxStrippableValueLen is the observed limit, in UTF-16 code units, up to which
// Active Directory strips ignorable code points from a String(Unicode) assertion
// value. Past it the inserted code points are no longer stripped and the result
// set changes, so the middleware caps its output at this length.
const MaxStrippableValueLen = 127

// InsertRunes inserts a random rune from pool into s at each inter-rune gap with
// probability prob, keeping the value within MaxStrippableValueLen UTF-16 code
// units (a variation selector costs two).
func InsertRunes(s string, pool []rune, prob float64) string {
	if prob <= 0 || len(pool) == 0 {
		return s
	}

	budget := MaxStrippableValueLen - len(utf16.Encode([]rune(s)))

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

// SubstituteSpaces replaces each ASCII space in s, with probability prob, by a
// random rune from pool (see AltSpaceRunes).
func SubstituteSpaces(s string, pool []rune, prob float64) string {
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

// foldClassSet returns the set of fold code points belonging to the named classes
// (see FoldClassMembers). An empty selection, or one containing "all", returns nil
// (every class); unknown names contribute nothing.
func foldClassSet(classes []string) map[rune]bool {
	if len(classes) == 0 {
		return nil
	}
	for _, c := range classes {
		if c == "all" {
			return nil
		}
	}
	set := map[rune]bool{}
	for _, c := range classes {
		for _, r := range FoldClassMembers[c] {
			set[r] = true
		}
	}
	return set
}

// parseFoldClasses turns a comma-separated class list into a code-point set (see
// foldClassSet); "all" or an empty string selects every class.
func parseFoldClasses(csv string) map[rune]bool {
	var classes []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			classes = append(classes, p)
		}
	}
	return foldClassSet(classes)
}

// FoldSubstituter holds the sort-key fold tables narrowed to a chosen set of fold
// classes, computed once so that substitution at request time is a plain random
// pick per character. Build it with NewFoldSubstituter.
type FoldSubstituter struct {
	single map[rune][]rune // lowercase base char -> substitutes in the selected classes
	ligs   []foldLigature  // n:1 folds, longest ASCII sequence first
}

type foldLigature struct {
	ascii string
	pool  []rune
}

// NewFoldSubstituter prepares the fold tables limited to the given comma-separated
// fold classes (see FoldClassMembers); "all" or an empty string selects every
// class. Base characters and ligatures left with no substitute by the restriction
// are dropped, so at substitution time a present entry always has a usable pool.
func NewFoldSubstituter(classes string) FoldSubstituter {
	allowed := parseFoldClasses(classes)
	restrict := func(pool []rune) []rune {
		if allowed == nil {
			return pool
		}
		var out []rune
		for _, r := range pool {
			if allowed[r] {
				out = append(out, r)
			}
		}
		return out
	}

	fs := FoldSubstituter{single: make(map[rune][]rune, len(SortKeyFoldMap))}
	for base, pool := range SortKeyFoldMap {
		if r := restrict(pool); len(r) > 0 {
			fs.single[base] = r
		}
	}
	// FoldLigatures is ordered longest-first; ranging preserves that order.
	for _, lg := range FoldLigatures {
		if r := restrict(lg.R); len(r) > 0 {
			fs.ligs = append(fs.ligs, foldLigature{lg.ASCII, r})
		}
	}
	return fs
}

// Apply rewrites s, replacing characters and ligature sequences with randomly
// chosen code points that AD's String(Unicode) comparison folds back to the
// original, each with probability prob. All substitutes are single BMP code
// points (1:1 in UTF-16), so no strip budget applies.
func (fs FoldSubstituter) Apply(s string, prob float64) string {
	if prob <= 0 {
		return s
	}

	rs := []rune(s)
	out := make([]rune, 0, len(rs))
	for i := 0; i < len(rs); {
		if pool, n, ok := fs.matchLigature(rs, i); ok && rand.Float64() < prob {
			out = append(out, pool[rand.Intn(len(pool))])
			i += n
			continue
		}
		if pool, ok := fs.single[foldKey(rs[i])]; ok && rand.Float64() < prob {
			out = append(out, pool[rand.Intn(len(pool))])
			i++
			continue
		}
		out = append(out, rs[i])
		i++
	}

	return string(out)
}

// matchLigature reports whether one of the (already class-filtered) n:1 folds
// starts at rs[i], case-insensitively, returning its substitute pool and the
// number of runes the ASCII sequence covers.
func (fs FoldSubstituter) matchLigature(rs []rune, i int) ([]rune, int, bool) {
	for _, lg := range fs.ligs {
		if i+len(lg.ascii) > len(rs) {
			continue
		}
		ok := true
		for j := 0; j < len(lg.ascii); j++ {
			if foldKey(rs[i+j]) != rune(lg.ascii[j]) {
				ok = false
				break
			}
		}
		if ok {
			return lg.pool, len(lg.ascii), true
		}
	}
	return nil, 0, false
}

// foldKey maps a rune to its fold-table key: the table is keyed by lowercase
// ASCII, so uppercase letters look up under their lowercase form.
func foldKey(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// TransformDNValues applies fn to the value half of every RDN in a DN string,
// not the attribute type or the ',' / '=' punctuation (AD requires ASCII there,
// and attribute names do not fold). It underpins applying the String(Unicode)
// fold/strip transforms to DN-syntax values.
func TransformDNValues(dn string, fn func(string) string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			parts[i] = kv[0] + "=" + fn(kv[1])
		}
	}
	return strings.Join(parts, ",")
}
