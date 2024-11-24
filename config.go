package main

import (
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
)

const GarbageCharset = "abcdefghijklmnopqrsutwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Taken from:
// https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-anr
// (Windows Server 2012)
var ANRSet = []string{
	"name", "displayname", "samaccountname",
	"givenname", "legacyexchangedn", "sn", "proxyaddresses",
	"physicaldeliveryofficename", "msds-additionalsamaccountName",
	"msds-phoneticcompanyname", "msds-phoneticdepartment",
	"msds-phoneticdisplayname", "msds-phoneticfirstname",
	"msds-phoneticlastname",
}

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
	'N': "NamesToANR",
	'n': "ANRGarbageSubstring",
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
	'S': "OIDSpacing",
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
		"Timestamp":            filtermid.RandTimestampSuffixFilterObf(true, true, 10),
		"Spacing":              filtermid.RandSpacingFilterObf(4),
		"AddBool":              filtermid.RandAddBoolFilterObf(4, 0.5),
		"DblNegBool":           filtermid.RandDblNegBoolFilterObf(2, 0.5),
		"DeMorganBool":         filtermid.RandDeMorganBoolFilterObf(0.5),
		"NamesToANR":           filtermid.ANRAttributeFilterObf(ANRSet),
		"ANRGarbageSubstring":  filtermid.ANRSubstringGarbageFilterObf(1, 6, GarbageCharset),
		"EqApproxMatch":        filtermid.ApproxMatchFilterObf(),
		"AddWildcard":          filtermid.RandAddWildcardFilterObf(1),
		"PrependZeros":         filtermid.RandPrependZerosFilterObf(2),
		"Garbage":              filtermid.RandGarbageFilterObf(2, GarbageCharset),
		"OIDAttribute":         filtermid.OIDAttributeFilterObf(3, true),
		"Case":                 filtermid.RandCaseFilterObf(0.6),
		"HexValue":             filtermid.RandHexValueFilterObf(0.2),
		"ReorderBool":          filtermid.RandBoolReorderFilterObf(),
		"ExactBitwiseBreakout": filtermid.ExactBitwiseBreakoutFilterObf(),
		"EqInclusion":          filtermid.EqualityByInclusionFilterObf(),
		"EqExclusion":          filtermid.EqualityByExclusionFilterObf(),
		"BitwiseDecomposition": filtermid.BitwiseDecomposeFilterObf(32, false),
	}

	attrListMidMap = map[string]attrlistmid.AttrListMiddleware{
		"Case":                attrlistmid.RandCaseAttrListObf(0.6),
		"OIDAttribute":        attrlistmid.OIDAttributeAttrListObf(),
		"OIDSpacing":          attrlistmid.RandOIDSpacingAttrListObf(5),
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
