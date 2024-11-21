package main

import (
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
)

const GarbageCharset = "abcdefghijklmnopqrsutwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	filterMidMap   map[string]filtermid.FilterMiddleware
	attrListMidMap map[string]attrlistmid.AttrListMiddleware
	baseDNMidMap   map[string]basednmid.BaseDNMiddleware
)

var filterMidFlags map[rune]string = map[rune]string{
	'S': "Spacing",
	'T': "Timestamp",
	'B': "AddBool",
	'D': "DblNegBool",
	'M': "DeMorganBool",
	//'N': "NamesToANR",
	'A': "EqApproxMatch",
	'W': "AddWildcard",
	'Z': "PrependZeros",
	'G': "Garbage",
	'O': "OIDAttribute",
	'C': "Case",
	'X': "HexValue",
	'R': "ReorderBool",
	'b': "ExactBitwiseBreakout",
	'I': "EqInclusion",
	'E': "EqExclusion",
	'd': "BitwiseDecomposition",
}

var baseDNMidFlags map[rune]string = map[rune]string{
	'C': "Case",
	'O': "OIDAttribute",
	'Z': "OIDPrependZeros",
	'S': "Spacing",
	'Q': "DoubleQuotes",
	'X': "HexValue",
}

var attrListMidFlags map[rune]string = map[rune]string{
	'C': "Case",
	'O': "OIDAttribute",
	'S': "Spacing",
	'D': "Duplicate",
	'g': "GarbageExisting",
	'G': "GarbageNonExisting",
	'W': "AddWildcard",
	'w': "ReplaceWithWildcard",
	'E': "ReplaceWithEmpty",
	'R': "ReorderList",
}

func SetupFilterMidMap(configFile string) {
	filterMidMap = map[string]filtermid.FilterMiddleware{
		"Timestamp":    filtermid.RandTimestampSuffixFilterObf(true, true, 10), // Trivial-prone
		"Spacing":      filtermid.RandSpacingFilterObf(2),                      // Unstable / Trivial-prone
		"AddBool":      filtermid.RandAddBoolFilterObf(4, 0.5),
		"DblNegBool":   filtermid.RandDblNegBoolFilterObf(2, 0.5),
		"DeMorganBool": filtermid.RandDeMorganBoolFilterObf(0.5),
		//"NamesToANR":   filtermid.ConvertNamesToANRFilterObf(),
		"EqApproxMatch":        filtermid.ApproxMatchFilterObf(),
		"AddWildcard":          filtermid.RandAddWildcardFilterObf(1),
		"PrependZeros":         filtermid.RandPrependZerosFilterObf(1, 2),
		"Garbage":              filtermid.RandGarbageFilterObf(2),
		"OIDAttribute":         filtermid.OIDAttributeFilterObf(3, true),
		"Case":                 filtermid.RandCaseFilterObf(0.6),
		"HexValue":             filtermid.RandHexValueFilterObf(0.2),          // Unstable / trivial-prone
		"ReorderBool":          filtermid.RandBoolReorderFilterObf(),          // Trivial-prone
		"ExactBitwiseBreakout": filtermid.ExactBitwiseBreakoutFilterObf(),     // Trivial-prone
		"EqInclusion":          filtermid.EqualityByInclusionFilterObf(),      // Unstable
		"EqExclusion":          filtermid.EqualityByExclusionFilterObf(),      // Unstable
		"BitwiseDecomposition": filtermid.BitwiseDecomposeFilterObf(3, false), // Trivial-prone
	}

	attrListMidMap = map[string]attrlistmid.AttrListMiddleware{
		"Case":                attrlistmid.RandCaseAttrListObf(0.6),
		"OIDAttribute":        attrlistmid.OIDAttributeAttrListObf(),
		"Spacing":             attrlistmid.RandSpacingAttrListObf(2),
		"Duplicate":           attrlistmid.DuplicateAttrListObf(1, 3),
		"GarbageExisting":     attrlistmid.GarbageExistingAttrListObf(5),
		"GarbageNonExisting":  attrlistmid.GarbageNonExistingAttrListObf(4, 8, GarbageCharset),
		"AddWildcard":         attrlistmid.AddWildcardAttrListObf(),
		"ReplaceWithWildcard": attrlistmid.ReplaceWithWildcardAttrListObf(),
		"ReplaceWithEmpty":    attrlistmid.ReplaceWithEmptyAttrListObf(),
		"ReorderList":         attrlistmid.ReorderListAttrListObf(),
	}

	baseDNMidMap = map[string]basednmid.BaseDNMiddleware{
		"Case":            basednmid.RandCaseBaseDNObf(0.6),
		"HexValue":        basednmid.RandHexValueBaseDNObf(0.2),
		"OIDAttribute":    basednmid.OIDAttributeBaseDNObf(),
		"Spacing":         basednmid.RandSpacingBaseDNObf(1, 4, 0.5),
		"DoubleQuotes":    basednmid.DoubleQuotesBaseDNObf(),
		"OIDPrependZeros": basednmid.OIDPrependZerosBaseDNObf(1, 4),
	}
}
