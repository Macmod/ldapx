package app

import (
	"fmt"
	"sort"
	"strings"
)

// validateChainRunes checks that every rune in chain is a registered
// middleware code in flags. It returns an error listing any unrecognized
// runes so callers can surface typos instead of silently dropping them.
func validateChainRunes(chain string, flags map[rune]string) error {
	var unknown []rune
	for _, c := range chain {
		if _, exists := flags[c]; !exists {
			unknown = append(unknown, c)
		}
	}

	if len(unknown) == 0 {
		return nil
	}

	sort.Slice(unknown, func(i, j int) bool {
		return unknown[i] < unknown[j]
	})

	var parts []string
	for _, c := range unknown {
		parts = append(parts, fmt.Sprintf("%q", string(c)))
	}

	return fmt.Errorf("unrecognized middleware code(s): %s", strings.Join(parts, ", "))
}
