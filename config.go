package main

import (
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/middlewares"
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
)

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
	't': "TimestampGarbage",
	'T': "ReplaceTautologies",
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
	'x': "EqExtensible",
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

func SetupMiddlewaresMap() {
	baseDNMidMap = map[string]basednmid.BaseDNMiddleware{
		"Case":            basednmid.RandCaseBaseDNObf(optFloat("BDNCaseProb")),
		"HexValue":        basednmid.RandHexValueBaseDNObf(optFloat("BDNHexValueProb")),
		"OIDAttribute":    basednmid.OIDAttributeBaseDNObf(),
		"Spacing":         basednmid.RandSpacingBaseDNObf(optInt("BDNSpacingMaxElems")),
		"DoubleQuotes":    basednmid.DoubleQuotesBaseDNObf(),
		"OIDPrependZeros": basednmid.OIDPrependZerosBaseDNObf(optInt("BDNOIDPrependZerosMaxElems")),
	}

	filterMidMap = map[string]filtermid.FilterMiddleware{
		"Spacing":              filtermid.RandSpacingFilterObf(optInt("FiltSpacingMaxSpaces")),
		"TimestampGarbage":     filtermid.RandTimestampSuffixFilterObf(optInt("FiltTimestampGarbageMaxChars"), optStr("FiltGarbageCharset")),
		"ReplaceTautologies":   filtermid.ReplaceTautologiesFilterObf(),
		"AddBool":              filtermid.RandAddBoolFilterObf(optInt("FiltAddBoolMaxDepth"), optFloat("FiltDeMorganBoolProb")),
		"DblNegBool":           filtermid.RandDblNegBoolFilterObf(optInt("FiltDblNegBoolMaxDepth"), optFloat("FiltDeMorganBoolProb")),
		"DeMorganBool":         filtermid.DeMorganBoolFilterObf(),
		"NamesToANR":           filtermid.ANRAttributeFilterObf(ANRSet),
		"ANRGarbageSubstring":  filtermid.ANRSubstringGarbageFilterObf(optInt("FiltANRSubstringMaxElems"), optStr("FiltGarbageCharset")),
		"EqApproxMatch":        filtermid.ApproxMatchFilterObf(),
		"AddWildcard":          filtermid.RandAddWildcardFilterObf(optFloat("FiltAddWildcardProb")),
		"PrependZeros":         filtermid.RandPrependZerosFilterObf(optInt("FiltPrependZerosMaxElems")),
		"Garbage":              filtermid.RandGarbageFilterObf(optInt("FiltGarbageMaxElems"), optInt("FiltGarbageMaxSize"), optStr("FiltGarbageCharset")),
		"OIDAttribute":         filtermid.OIDAttributeFilterObf(optInt("FiltOIDAttributeMaxElems"), optBool("FiltOIDAttributePrependOID")),
		"Case":                 filtermid.RandCaseFilterObf(optFloat("FiltCaseProb")),
		"HexValue":             filtermid.RandHexValueFilterObf(optFloat("FiltHexValueProb")),
		"ReorderBool":          filtermid.RandBoolReorderFilterObf(),
		"ExactBitwiseBreakout": filtermid.ExactBitwiseBreakoutFilterObf(),
		"EqInclusion":          filtermid.EqualityByInclusionFilterObf(),
		"EqExclusion":          filtermid.EqualityByExclusionFilterObf(),
		"EqExtensible":         filtermid.EqualityToExtensibleFilterObf(optBool("FiltEqExtensibleAppendDN")),
		"BitwiseDecomposition": filtermid.BitwiseDecomposeFilterObf(optInt("FiltBitwiseDecompositionMaxBits")),
	}

	attrListMidMap = map[string]attrlistmid.AttrListMiddleware{
		"Case":                attrlistmid.RandCaseAttrListObf(optFloat("FiltCaseProb")),
		"OIDAttribute":        attrlistmid.OIDAttributeAttrListObf(),
		"OIDSpacing":          attrlistmid.RandOIDSpacingAttrListObf(optInt("AttrsOIDSpacingMaxElems")),
		"Duplicate":           attrlistmid.DuplicateAttrListObf(optFloat("AttrsDuplicateProb")),
		"GarbageExisting":     attrlistmid.GarbageExistingAttrListObf(optInt("AttrsGarbageExistingMaxElems")),
		"GarbageNonExisting":  attrlistmid.GarbageNonExistingAttrListObf(optInt("AttrsGarbageNonExistingMaxElems"), optInt("AttrsGarbageNonExistingMaxSize"), optStr("FiltGarbageCharset")),
		"AddWildcard":         attrlistmid.AddWildcardAttrListObf(),
		"ReplaceWithWildcard": attrlistmid.ReplaceWithWildcardAttrListObf(),
		"ReplaceWithEmpty":    attrlistmid.ReplaceWithEmptyAttrListObf(),
		"ReorderList":         attrlistmid.ReorderListAttrListObf(),
	}
}

func optStr(key string) string {
	if value, ok := options.Get(key); ok {
		return value
	}
	return middlewares.DefaultOptions[key]
}

func optInt(key string) int {
	if value, ok := options.Get(key); ok {
		i, err := strconv.Atoi(value)
		if err == nil {
			return i
		}
	}

	result, _ := strconv.Atoi(middlewares.DefaultOptions[key])
	return result
}

func optFloat(key string) float64 {
	if value, ok := options.Get(key); ok {
		i, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return i
		}
	}

	result, _ := strconv.ParseFloat(middlewares.DefaultOptions[key], 64)
	return result
}

func optBool(key string) bool {
	if value, ok := options.Get(key); ok {
		return strings.ToLower(value) == "true"
	}
	return strings.ToLower(middlewares.DefaultOptions[key]) == "true"
}
