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
	baseDNMidMap   map[string]basednmid.BaseDNMiddleware
	filterMidMap   map[string]filtermid.FilterMiddleware
	attrListMidMap map[string]attrlistmid.AttrListMiddleware
)

var baseDNMidFlags map[rune]string = map[rune]string{
	'O': "OIDAttribute",
	'C': "Case",
	'X': "HexValue",
	'S': "Spacing",
	'Q': "DoubleQuotes",
}

var filterMidFlags map[rune]string = map[rune]string{
	'O': "OIDAttribute",
	'C': "Case",
	'X': "HexValue",
	'S': "Spacing",
	'T': "ReplaceTautologies",
	't': "TimestampGarbage",
	'B': "AddBool",
	'D': "DblNegBool",
	'M': "DeMorganBool",
	'R': "ReorderBool",
	'b': "ExactBitwiseBreakout",
	'd': "BitwiseDecomposition",
	'I': "EqInclusion",
	'E': "EqExclusion",
	'G': "Garbage",
	'A': "EqApproxMatch",
	'x': "EqExtensible",
	'Z': "PrependZeros",
	's': "SubstringSplit",
	'N': "NamesToANR",
	'n': "ANRGarbageSubstring",
}

var attrListMidFlags map[rune]string = map[rune]string{
	'O': "OIDAttribute",
	'C': "Case",
	'D': "Duplicate",
	'G': "GarbageNonExisting",
	'g': "GarbageExisting",
	'W': "ReplaceWithWildcard",
	'w': "AddWildcard",
	'p': "AddPlus",
	'E': "ReplaceWithEmpty",
	'R': "ReorderList",
}

func SetupMiddlewaresMap() {
	baseDNMidMap = map[string]basednmid.BaseDNMiddleware{
		"OIDAttribute": basednmid.OIDAttributeBaseDNObf(optInt("BDNOIDAttributeMaxSpaces"), optInt("AttrsOIDAttributeMaxZeros"), optBool("AttrsOIDAttributePrefix")),
		"Case":         basednmid.RandCaseBaseDNObf(optFloat("BDNCaseProb")),
		"HexValue":     basednmid.RandHexValueBaseDNObf(optFloat("BDNHexValueProb")),
		"Spacing":      basednmid.RandSpacingBaseDNObf(optInt("BDNSpacingMaxElems")),
		"DoubleQuotes": basednmid.DoubleQuotesBaseDNObf(),
	}

	filterMidMap = map[string]filtermid.FilterMiddleware{
		"OIDAttribute":         filtermid.OIDAttributeFilterObf(optInt("FiltOIDAttributeMaxSpaces"), optInt("FiltOIDAttributeMaxZeros"), optBool("FiltOIDAttributePrefix")),
		"Case":                 filtermid.RandCaseFilterObf(optFloat("FiltCaseProb")),
		"HexValue":             filtermid.RandHexValueFilterObf(optFloat("FiltHexValueProb")),
		"Spacing":              filtermid.RandSpacingFilterObf(optInt("FiltSpacingMaxSpaces")),
		"ReplaceTautologies":   filtermid.ReplaceTautologiesFilterObf(),
		"TimestampGarbage":     filtermid.RandTimestampSuffixFilterObf(optInt("FiltTimestampGarbageMaxChars"), optStr("FiltGarbageCharset"), optBool("FiltTimestampGarbageUseComma")),
		"AddBool":              filtermid.RandAddBoolFilterObf(optInt("FiltAddBoolMaxDepth"), optFloat("FiltDeMorganBoolProb")),
		"DblNegBool":           filtermid.RandDblNegBoolFilterObf(optInt("FiltDblNegBoolMaxDepth"), optFloat("FiltDeMorganBoolProb")),
		"DeMorganBool":         filtermid.DeMorganBoolFilterObf(),
		"ReorderBool":          filtermid.RandBoolReorderFilterObf(),
		"ExactBitwiseBreakout": filtermid.ExactBitwiseBreakoutFilterObf(),
		"BitwiseDecomposition": filtermid.BitwiseDecomposeFilterObf(optInt("FiltBitwiseDecompositionMaxBits")),
		"EqInclusion":          filtermid.EqualityByInclusionFilterObf(),
		"EqExclusion":          filtermid.EqualityByExclusionFilterObf(),
		"Garbage":              filtermid.RandGarbageFilterObf(optInt("FiltGarbageMaxElems"), optInt("FiltGarbageMaxSize"), optStr("FiltGarbageCharset")),
		"EqApproxMatch":        filtermid.EqualityToApproxMatchFilterObf(),
		"EqExtensible":         filtermid.EqualityToExtensibleFilterObf(optBool("FiltEqExtensibleAppendDN")),
		"PrependZeros":         filtermid.RandPrependZerosFilterObf(optInt("FiltPrependZerosMaxElems")),
		"SubstringSplit":       filtermid.RandSubstringSplitFilterObf(optFloat("FiltSubstringSplitProb")),
		"NamesToANR":           filtermid.ANRAttributeFilterObf(ANRSet),
		"ANRGarbageSubstring":  filtermid.ANRSubstringGarbageFilterObf(optInt("FiltANRSubstringMaxElems"), optStr("FiltGarbageCharset")),
	}

	attrListMidMap = map[string]attrlistmid.AttrListMiddleware{
		"OIDAttribute":        attrlistmid.OIDAttributeAttrListObf(optInt("AttrsOIDAttributeMaxSpaces"), optInt("AttrsOIDAttributeMaxZeros"), optBool("AttrsOIDAttributePrefix")),
		"Case":                attrlistmid.RandCaseAttrListObf(optFloat("FiltCaseProb")),
		"Duplicate":           attrlistmid.DuplicateAttrListObf(optFloat("AttrsDuplicateProb")),
		"GarbageNonExisting":  attrlistmid.GarbageNonExistingAttrListObf(optInt("AttrsGarbageNonExistingMaxElems"), optInt("AttrsGarbageNonExistingMaxSize"), optStr("FiltGarbageCharset")),
		"GarbageExisting":     attrlistmid.GarbageExistingAttrListObf(optInt("AttrsGarbageExistingMaxElems")),
		"ReplaceWithWildcard": attrlistmid.ReplaceWithWildcardAttrListObf(),
		"AddWildcard":         attrlistmid.AddWildcardAttrListObf(),
		"AddPlus":             attrlistmid.AddPlusAttrListObf(),
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
