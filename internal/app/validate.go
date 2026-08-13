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

// exclusiveBaseDNMids are the BaseDN middlewares that replace the BaseDN with
// an alternative DN form carrying no DN of its own (MS-ADTS 3.1.1.3.1.2.4).
// Nothing before them survives the replacement, and nothing after them has a DN
// left to work on, so they are only allowed as the entire chain.
var exclusiveBaseDNMids = map[rune]string{
	'U': "GUIDFormat",
	'I': "SIDFormat",
}

// wkGUIDPredecessors are the BaseDN middlewares that may precede WKGUIDFormat.
// A predecessor must leave the leading RDN of the BaseDN matchable by
// WKGUIDFormat's case-insensitive comparison against its container table;
// anything else silently turns WKGUIDFormat into a no-op, and should be placed
// after it instead, where it applies to the object_DN of the resulting form.
var wkGUIDPredecessors = map[rune]bool{
	'C': true,
}

// requiredBaseDNOptions maps a BaseDN middleware to the option it cannot
// operate without.
var requiredBaseDNOptions = map[rune]string{
	'U': "BDNGuid",
	'I': "BDNSid",
}

// validateBaseDNChain checks the BaseDN chain for unknown codes, for exclusive
// middlewares sharing the chain with others, for middlewares that would keep
// WKGUIDFormat from matching, and for middlewares whose required options are
// unset.
func validateBaseDNChain(chain string) error {
	if err := validateChainRunes(chain, baseDNMidFlags); err != nil {
		return err
	}

	runes := []rune(chain)
	for i, c := range runes {
		if name, isExclusive := exclusiveBaseDNMids[c]; isExclusive && len(runes) > 1 {
			return fmt.Errorf("middleware %q (%s) must be the only one in the basedn chain", string(c), name)
		}

		if c == 'W' && i > 0 {
			for _, prev := range runes[:i] {
				if prev == c {
					return fmt.Errorf("middleware %q (%s) cannot appear more than once in the basedn chain", string(c), baseDNMidFlags[c])
				}

				if !wkGUIDPredecessors[prev] {
					return fmt.Errorf(
						"middleware %q (%s) cannot be preceded by %q (%s) in the basedn chain - place it after %q instead",
						string(c), baseDNMidFlags[c], string(prev), baseDNMidFlags[prev], string(c),
					)
				}
			}
		}

		if option, required := requiredBaseDNOptions[c]; required && optStr(option) == "" {
			return fmt.Errorf("middleware %q (%s) requires the %s option to be set", string(c), baseDNMidFlags[c], option)
		}
	}

	return nil
}

// validateFilterChain checks the filter chain for unknown codes and for
// middlewares whose required options are unset.
func validateFilterChain(chain string) error {
	if err := validateChainRunes(chain, filterMidFlags); err != nil {
		return err
	}

	if strings.ContainsRune(chain, 'F') && optStr("FiltObjCategoryRootDN") == "" {
		return fmt.Errorf("middleware \"F\" (ObjectCategoryForm) requires the FiltObjCategoryRootDN option to be set")
	}

	return nil
}
