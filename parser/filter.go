package parser

import (
	"bytes"
	hexpac "encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
)

/*
   Parser for raw (packet-level) LDAP search filters
   References:
	- RFC4510 - LDAP: Technical Specification
	- RFC4515 - LDAP: String Representation of Search Filters
	- DEFCON32 - MaLDAPtive
*/

// FilterType represents the various LDAP filter types.
type FilterType int

const (
	And FilterType = iota
	Or
	Not
	EqualityMatch
	Substring
	GreaterOrEqual
	LessOrEqual
	Present
	ApproxMatch
	ExtensibleMatch
)

// Filter is an interface for all LDAP filter types.
type Filter interface {
	// Type returns the type of the filter.
	Type() FilterType
}

// Base structs for different filter types:

// FilterAnd represents an AND filter.
type FilterAnd struct {
	Filters []Filter
}

func (f *FilterAnd) Type() FilterType { return And }

// FilterOr represents an OR filter.
type FilterOr struct {
	Filters []Filter
}

func (f *FilterOr) Type() FilterType { return Or }

// FilterNot represents a NOT filter.
type FilterNot struct {
	Filter Filter
}

func (f *FilterNot) Type() FilterType { return Not }

// FilterEqualityMatch represents an equality match filter.
type FilterEqualityMatch struct {
	AttributeDesc  string
	AssertionValue string
}

func (f *FilterEqualityMatch) Type() FilterType { return EqualityMatch }

// FilterPresent represents a presence filter.
type FilterPresent struct {
	AttributeDesc string
}

func (f *FilterPresent) Type() FilterType { return Present }

// FilterSubstring represents a substring filter.
type FilterSubstring struct {
	AttributeDesc string
	Substrings    []SubstringFilter
}

func (f *FilterSubstring) Type() FilterType { return Substring }

// FilterGreaterOrEqual represents a greater-or-equal filter.
type FilterGreaterOrEqual struct {
	AttributeDesc  string
	AssertionValue string
}

func (f *FilterGreaterOrEqual) Type() FilterType { return GreaterOrEqual }

// FilterLessOrEqual represents a less-or-equal filter.
type FilterLessOrEqual struct {
	AttributeDesc  string
	AssertionValue string
}

func (f *FilterLessOrEqual) Type() FilterType { return LessOrEqual }

// FilterApproxMatch represents an approximate match filter.
type FilterApproxMatch struct {
	AttributeDesc  string
	AssertionValue string
}

func (f *FilterApproxMatch) Type() FilterType { return ApproxMatch }

// FilterExtensibleMatch represents an extensible match filter.
type FilterExtensibleMatch struct {
	MatchingRule  string
	AttributeDesc string
	MatchValue    string
	DNAttributes  bool
}

func (f *FilterExtensibleMatch) Type() FilterType { return ExtensibleMatch }

// SubstringFilter represents a component of a substring filter.
// Either Initial, Any or Final will be set.
type SubstringFilter struct {
	Initial string
	Any     string
	Final   string
}

// Converts a BER packet into a Filter structure
func PacketToFilter(packet *ber.Packet) (Filter, error) {
	switch packet.Tag {
	case 0x0: // AND filter
		var filters []Filter
		for _, child := range packet.Children {
			subFilter, err := PacketToFilter(child)
			if err != nil {
				return nil, err
			}
			filters = append(filters, subFilter)
		}
		return &FilterAnd{Filters: filters}, nil

	case 0x1: // OR filter
		var filters []Filter
		for _, child := range packet.Children {
			subFilter, err := PacketToFilter(child)
			if err != nil {
				return nil, err
			}
			filters = append(filters, subFilter)
		}
		return &FilterOr{Filters: filters}, nil

	case 0x2: // NOT filter
		if len(packet.Children) != 1 {
			return nil, fmt.Errorf("NOT filter should have exactly 1 child")
		}
		subFilter, err := PacketToFilter(packet.Children[0])
		if err != nil {
			return nil, err
		}
		return &FilterNot{Filter: subFilter}, nil

	case 0x3: // Equality Match filter (e.g., (cn=John))
		if len(packet.Children) != 2 {
			return nil, fmt.Errorf("Equality match filter should have 2 children")
		}
		attr := string(packet.Children[0].Data.Bytes())
		value := string(packet.Children[1].Data.Bytes())
		return &FilterEqualityMatch{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x4: // Substring filter (e.g., (cn=Jo*hn))
		if len(packet.Children) < 2 {
			return nil, fmt.Errorf("Substring filter should have at least 2 children")
		}

		attr := string(packet.Children[0].Data.Bytes())
		var substrs []SubstringFilter
		for _, subPacket := range packet.Children[1].Children {
			switch int(subPacket.Tag) {
			case 0x0: // Initial
				substrs = append(substrs, SubstringFilter{Initial: string(subPacket.Data.Bytes())})
			case 0x1: // Any
				substrs = append(substrs, SubstringFilter{Any: string(subPacket.Data.Bytes())})
			case 0x2: // Final
				substrs = append(substrs, SubstringFilter{Final: string(subPacket.Data.Bytes())})
			}
		}

		return &FilterSubstring{
			AttributeDesc: attr,
			Substrings:    substrs,
		}, nil

	case 0x5: // GreaterOrEqual filter (e.g., (age>=25))
		if len(packet.Children) != 2 {
			return nil, fmt.Errorf("GreaterOrEqual filter should have 2 children")
		}
		attr := string(packet.Children[0].Data.Bytes())
		value := string(packet.Children[1].Data.Bytes())
		return &FilterGreaterOrEqual{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x6: // LessOrEqual filter (e.g., (age<=30))
		if len(packet.Children) != 2 {
			return nil, fmt.Errorf("LessOrEqual filter should have 2 children")
		}
		attr := string(packet.Children[0].Data.Bytes())
		value := string(packet.Children[1].Data.Bytes())
		return &FilterLessOrEqual{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x7: // Present filter (e.g., (cn=))
		if packet.Data.Len() < 1 {
			return nil, fmt.Errorf("Present filter should have data")
		}

		attr := packet.Data.String()
		return &FilterPresent{
			AttributeDesc: attr,
		}, nil

	case 0x8: // ApproxMatch filter (e.g., (cn~=John))
		if len(packet.Children) != 2 {
			return nil, fmt.Errorf("ApproxMatch filter should have 2 children")
		}
		attr := string(packet.Children[0].Data.Bytes())
		value := string(packet.Children[1].Data.Bytes())
		return &FilterApproxMatch{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x9: // ExtensibleMatch filter
		if len(packet.Children) < 2 {
			return nil, fmt.Errorf("ExtensibleMatch filter should have at least 2 children")
		}

		// Parsing the different components of ExtensibleMatch
		var matchingRule string
		var attributeDesc, matchValue string
		var dnAttributes bool

		// Check for optional components
		for _, child := range packet.Children {
			switch int(child.Tag) {
			case 0x1: // MatchingRuleID
				matchingRule = string(child.Data.Bytes())
			case 0x2: // AttributeDescription
				attributeDesc = string(child.Data.Bytes())
			case 0x3: // MatchValue
				matchValue = string(child.Data.Bytes())
			case 0x4: // DNAttributes (True/False)
				dnAttributes = len(child.Data.Bytes()) > 0 && child.Data.Bytes()[0] == 0xFF
			}
		}

		// Create the ExtensibleMatch filter
		return &FilterExtensibleMatch{
			MatchingRule:  matchingRule,
			AttributeDesc: attributeDesc,
			MatchValue:    matchValue,
			DNAttributes:  dnAttributes,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported filter type with tag: %x", packet.Tag)
	}
}

func FilterToString(filter Filter, level int) string {
	var result strings.Builder
	indent := strings.Repeat("  ", level)
	result.WriteString(fmt.Sprintf("%sFilter Type: %v\n", indent, filter.Type()))

	switch f := filter.(type) {
	case *FilterAnd:
		result.WriteString(fmt.Sprintf("%sAND Filter with %d sub-filters:\n", indent, len(f.Filters)))
		for _, subFilter := range f.Filters {
			result.WriteString(FilterToString(subFilter, level+1))
		}
	case *FilterOr:
		result.WriteString(fmt.Sprintf("%sOR Filter with %d sub-filters:\n", indent, len(f.Filters)))
		for _, subFilter := range f.Filters {
			result.WriteString(FilterToString(subFilter, level+1))
		}
	case *FilterNot:
		result.WriteString(fmt.Sprintf("%sNOT Filter:\n", indent))
		result.WriteString(FilterToString(f.Filter, level+1))
	case *FilterEqualityMatch:
		result.WriteString(fmt.Sprintf("%sEquality Match - Attribute: %s, Value: %s\n", indent, f.AttributeDesc, f.AssertionValue))
	case *FilterPresent:
		result.WriteString(fmt.Sprintf("%sPresent Filter - Attribute: %s\n", indent, f.AttributeDesc))
	case *FilterSubstring:
		result.WriteString(fmt.Sprintf("%sSubstring Filter - Attribute: %s (Length %d)\n", indent, f.AttributeDesc, len(f.Substrings)))
		for _, sub := range f.Substrings {
			if sub.Initial != "" {
				result.WriteString(fmt.Sprintf("%s  Initial: %s\n", indent, sub.Initial))
			}
			if sub.Any != "" {
				result.WriteString(fmt.Sprintf("%s  Any: %s\n", indent, sub.Any))
			}
			if sub.Final != "" {
				result.WriteString(fmt.Sprintf("%s  Final: %s\n", indent, sub.Final))
			}
		}
	case *FilterGreaterOrEqual:
		result.WriteString(fmt.Sprintf("%sGreater Or Equal - Attribute: %s, Value: %s\n", indent, f.AttributeDesc, f.AssertionValue))
	case *FilterLessOrEqual:
		result.WriteString(fmt.Sprintf("%sLess Or Equal - Attribute: %s, Value: %s\n", indent, f.AttributeDesc, f.AssertionValue))
	case *FilterApproxMatch:
		result.WriteString(fmt.Sprintf("%sApprox Match - Attribute: %s, Value: %s\n", indent, f.AttributeDesc, f.AssertionValue))
	case *FilterExtensibleMatch:
		result.WriteString(fmt.Sprintf("%sExtensible Match - Matching Rule: %s, Attribute: %s, Value: %s, DN Attributes: %t\n",
			indent, f.MatchingRule, f.AttributeDesc, f.MatchValue, f.DNAttributes))
	default:
		result.WriteString(fmt.Sprintf("%sUnknown filter type.\n", indent))
	}

	return result.String()
}

func FilterToPacket(f Filter) *ber.Packet {
	switch filter := f.(type) {
	case *FilterAnd:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x0, nil, "")
		for _, subFilter := range filter.Filters {
			packet.AppendChild(FilterToPacket(subFilter))
		}
		return packet

	case *FilterOr:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x1, nil, "")
		for _, subFilter := range filter.Filters {
			packet.AppendChild(FilterToPacket(subFilter))
		}
		return packet

	case *FilterNot:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x2, nil, "")
		packet.AppendChild(FilterToPacket(filter.Filter))
		return packet

	case *FilterEqualityMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x3, nil, "")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, ""))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, ""))
		return packet

	case *FilterSubstring:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x4, nil, "")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, ""))

		substrings := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for _, substr := range filter.Substrings {
			if substr.Initial != "" {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x0, substr.Initial, ""))
			}
			if substr.Any != "" {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x1, substr.Any, ""))
			}
			if substr.Final != "" {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, substr.Final, ""))
			}
		}
		packet.AppendChild(substrings)
		return packet

	case *FilterGreaterOrEqual:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x5, nil, "")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, ""))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, ""))
		return packet

	case *FilterLessOrEqual:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x6, nil, "")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, ""))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, ""))
		return packet

	case *FilterPresent:
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x7, filter.AttributeDesc, "")

	case *FilterApproxMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x8, nil, "")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, ""))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, ""))
		return packet

	case *FilterExtensibleMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x9, nil, "")
		if filter.MatchingRule != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x1, filter.MatchingRule, ""))
		}
		if filter.AttributeDesc != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, filter.AttributeDesc, ""))
		}
		if filter.MatchValue != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x3, filter.MatchValue, ""))
		}
		if filter.DNAttributes {
			packet.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, 0x4, true, ""))
		}
		return packet
	}

	return nil
}

// Conversions from Filter to Query and vice-versa
func FilterToQuery(filter Filter) (string, error) {
	switch f := filter.(type) {
	case *FilterAnd:
		var subFilters []string
		for _, subFilter := range f.Filters {
			subStr, err := FilterToQuery(subFilter)
			if err != nil {
				return "", err
			}
			subFilters = append(subFilters, subStr)
		}
		return "(&" + strings.Join(subFilters, "") + ")", nil

	case *FilterOr:
		var subFilters []string
		for _, subFilter := range f.Filters {
			subStr, err := FilterToQuery(subFilter)
			if err != nil {
				return "", err
			}
			subFilters = append(subFilters, subStr)
		}
		return "(|" + strings.Join(subFilters, "") + ")", nil

	case *FilterNot:
		subStr, err := FilterToQuery(f.Filter)
		if err != nil {
			return "", err
		}
		return "(!" + subStr + ")", nil

	case *FilterEqualityMatch:
		return fmt.Sprintf("(%s=%s)", ldapEscape(f.AttributeDesc), ldapEscape(f.AssertionValue)), nil

	case *FilterSubstring:
		var parts []string
		for _, part := range f.Substrings {
			switch {
			case part.Initial != "":
				parts = append(parts, ldapEscape(part.Initial))
			case part.Any != "":
				parts = append(parts, ldapEscape(part.Any))
			case part.Final != "":
				parts = append(parts, ldapEscape(part.Final))
			}
		}

		// Handle edge cases
		if len(parts) > 0 {
			if f.Substrings[0].Initial == "" {
				parts[0] = "*" + parts[0]
			}
			if f.Substrings[len(f.Substrings)-1].Final == "" {
				parts[len(parts)-1] = parts[len(parts)-1] + "*"
			}
		}

		return fmt.Sprintf("(%s=%s)", ldapEscape(f.AttributeDesc), strings.Join(parts, "*")), nil
	case *FilterGreaterOrEqual:
		return fmt.Sprintf("(%s>=%s)", ldapEscape(f.AttributeDesc), ldapEscape(f.AssertionValue)), nil

	case *FilterLessOrEqual:
		return fmt.Sprintf("(%s<=%s)", ldapEscape(f.AttributeDesc), ldapEscape(f.AssertionValue)), nil

	case *FilterPresent:
		return fmt.Sprintf("(%s=*)", ldapEscape(f.AttributeDesc)), nil

	case *FilterApproxMatch:
		return fmt.Sprintf("(%s~=%s)", ldapEscape(f.AttributeDesc), ldapEscape(f.AssertionValue)), nil

	case *FilterExtensibleMatch:
		var parts []string
		if f.AttributeDesc != "" {
			parts = append(parts, ldapEscape(f.AttributeDesc))
		}
		if f.DNAttributes {
			parts = append(parts, "dn")
		}
		if f.MatchingRule != "" {
			parts = append(parts, ldapEscape(f.MatchingRule))
		}
		if f.MatchValue != "" {
			parts = append(parts, "="+ldapEscape(f.MatchValue))
		}
		return fmt.Sprintf("(%s)", strings.Join(parts, ":")), nil

	default:
		return "", fmt.Errorf("unsupported filter type: %T", filter)
	}
}

func QueryToFilter(query string) (Filter, error) {
	query = strings.TrimSpace(query)
	if len(query) == 0 {
		return nil, fmt.Errorf("empty query string")
	}

	if query[0] != '(' || query[len(query)-1] != ')' {
		return nil, fmt.Errorf("invalid query format")
	}

	var filter Filter
	var err error

	switch query[1] {
	case '&':
		filter, err = parseAndFilter(query)
	case '|':
		filter, err = parseOrFilter(query)
	case '!':
		filter, err = parseNotFilter(query)
	default:
		filter, err = parseSimpleFilter(query)
	}

	if err != nil {
		return nil, err
	}

	return filter, nil
}

func parseAndFilter(query string) (Filter, error) {
	subFilters, err := parseSubFilters(query[2 : len(query)-1])
	if err != nil {
		return nil, err
	}
	return &FilterAnd{Filters: subFilters}, nil
}

func parseOrFilter(query string) (Filter, error) {
	subFilters, err := parseSubFilters(query[2 : len(query)-1])
	if err != nil {
		return nil, err
	}
	return &FilterOr{Filters: subFilters}, nil
}

func parseNotFilter(query string) (Filter, error) {
	if len(query) < 4 {
		return nil, fmt.Errorf("invalid NOT filter")
	}
	subFilter, err := QueryToFilter(query[2 : len(query)-1])
	if err != nil {
		return nil, err
	}
	return &FilterNot{Filter: subFilter}, nil
}

func decodeEscapedSymbols(src []byte) (string, error) {
	var (
		buffer  bytes.Buffer
		offset  int
		reader  = bytes.NewReader(src)
		byteHex []byte
		byteVal []byte
	)

	for {
		runeVal, runeSize, err := reader.ReadRune()
		if err == io.EOF {
			return buffer.String(), nil
		} else if err != nil {
			return "", NewError(ErrorFilterCompile, fmt.Errorf("ldap: failed to read filter: %v", err))
		} else if runeVal == unicode.ReplacementChar {
			return "", NewError(ErrorFilterCompile, fmt.Errorf("ldap: error reading rune at position %d", offset))
		}

		if runeVal == '\\' {
			// http://tools.ietf.org/search/rfc4515
			// \ (%x5C) is not a valid character unless it is followed by two HEX characters due to not
			// being a member of UTF1SUBSET.
			if byteHex == nil {
				byteHex = make([]byte, 2)
				byteVal = make([]byte, 1)
			}

			if _, err := io.ReadFull(reader, byteHex); err != nil {
				if err == io.ErrUnexpectedEOF {
					return "", NewError(ErrorFilterCompile, errors.New("ldap: missing characters for escape in filter"))
				}
				return "", NewError(ErrorFilterCompile, fmt.Errorf("ldap: invalid characters for escape in filter: %v", err))
			}

			if _, err := hexpac.Decode(byteVal, byteHex); err != nil {
				return "", NewError(ErrorFilterCompile, fmt.Errorf("ldap: invalid characters for escape in filter: %v", err))
			}

			buffer.Write(byteVal)
		} else {
			buffer.WriteRune(runeVal)
		}

		offset += runeSize
	}
}

func parseSimpleFilter(query string) (Filter, error) {
	const (
		stateReadingAttr = iota
		stateReadingExtensibleMatchingRule
		stateReadingCondition
	)

	dnAttributes := false
	attribute := bytes.NewBuffer(nil)
	matchingRule := bytes.NewBuffer(nil)
	condition := bytes.NewBuffer(nil)

	query = strings.TrimSpace(query)
	if len(query) < 3 || query[0] != '(' || query[len(query)-1] != ')' {
		return nil, fmt.Errorf("invalid simple filter format")
	}

	var resultFilter Filter

	state := stateReadingAttr
	pos := 1
	for pos < len(query) {
		remainingQuery := query[pos:]
		char, width := utf8.DecodeRuneInString(remainingQuery)
		if char == ')' {
			break
		}

		if char == utf8.RuneError {
			return nil, fmt.Errorf("ldap: error reading rune at position %d", pos)
		}

		switch state {
		case stateReadingAttr:
			switch {
			case char == ':' && strings.HasPrefix(remainingQuery, ":dn:="):
				dnAttributes = true
				state = stateReadingCondition
				resultFilter = &FilterExtensibleMatch{}
				pos += 5
			case char == ':' && strings.HasPrefix(remainingQuery, ":dn:"):
				dnAttributes = true
				state = stateReadingExtensibleMatchingRule
				resultFilter = &FilterExtensibleMatch{}
				pos += 4
			case char == ':' && strings.HasPrefix(remainingQuery, ":="):
				state = stateReadingCondition
				resultFilter = &FilterExtensibleMatch{}
				pos += 2
			case char == ':':
				state = stateReadingExtensibleMatchingRule
				resultFilter = &FilterExtensibleMatch{}
				pos++
			case char == '=':
				state = stateReadingCondition
				resultFilter = &FilterEqualityMatch{}
				pos++
			case char == '>' && strings.HasPrefix(remainingQuery, ">="):
				state = stateReadingCondition
				resultFilter = &FilterGreaterOrEqual{}
				pos += 2
			case char == '<' && strings.HasPrefix(remainingQuery, "<="):
				state = stateReadingCondition
				resultFilter = &FilterLessOrEqual{}
				pos += 2
			case char == '~' && strings.HasPrefix(remainingQuery, "~="):
				state = stateReadingCondition
				resultFilter = &FilterApproxMatch{}
				pos += 2
			default:
				attribute.WriteRune(char)
				pos += width
			}

		case stateReadingExtensibleMatchingRule:
			switch {
			case char == ':' && strings.HasPrefix(remainingQuery, ":="):
				state = stateReadingCondition
				pos += 2
			default:
				matchingRule.WriteRune(char)
				pos += width
			}

		case stateReadingCondition:
			condition.WriteRune(char)
			pos += width
		}
	}

	if pos == len(query) {
		return nil, fmt.Errorf("ldap: unexpected end of filter")
	}

	if resultFilter == nil {
		return nil, fmt.Errorf("ldap: error parsing filter")
	}

	encodedString, encodeErr := decodeEscapedSymbols(condition.Bytes())
	if encodeErr != nil {
		return nil, fmt.Errorf("Error decoding escaped symbols")
	}

	switch resultFilter := resultFilter.(type) {
	case *FilterExtensibleMatch:
		resultFilter.MatchingRule = matchingRule.String()
		resultFilter.AttributeDesc = attribute.String()
		resultFilter.MatchValue = encodedString
		resultFilter.DNAttributes = dnAttributes
		return resultFilter, nil
	case *FilterApproxMatch:
		resultFilter.AttributeDesc = attribute.String()
		resultFilter.AssertionValue = encodedString
		return resultFilter, nil
	case *FilterGreaterOrEqual:
		resultFilter.AttributeDesc = attribute.String()
		resultFilter.AssertionValue = encodedString
		return resultFilter, nil
	case *FilterLessOrEqual:
		resultFilter.AttributeDesc = attribute.String()
		resultFilter.AssertionValue = encodedString
		return resultFilter, nil
	case *FilterEqualityMatch:
		if bytes.Equal(condition.Bytes(), []byte{'*'}) {
			// Looks like an equality match, but it's actually a presence filter
			return &FilterPresent{
				AttributeDesc: attribute.String(),
			}, nil
		} else if bytes.Contains(condition.Bytes(), []byte{'*'}) { // Review to use bytes
			// Looks like an equality match, but it's actually a substring filter
			substrs := make([]SubstringFilter, 0)
			parts := bytes.Split(condition.Bytes(), []byte{'*'})
			for i, part := range parts {
				if len(part) == 0 {
					continue
				}

				encodedString, encodeErr := decodeEscapedSymbols(part)
				if encodeErr != nil {
					return nil, fmt.Errorf("Error decoding escaped symbols")
				}

				switch i {
				case 0:
					substrs = append(substrs, SubstringFilter{
						Initial: encodedString,
					})
				case len(parts) - 1:
					substrs = append(substrs, SubstringFilter{
						Final: encodedString,
					})
				default:
					substrs = append(substrs, SubstringFilter{
						Any: encodedString,
					})
				}
			}

			return &FilterSubstring{
				AttributeDesc: attribute.String(),
				Substrings:    substrs,
			}, nil
		} else {
			// It's actually an equality match
			resultFilter.AttributeDesc = attribute.String()
			resultFilter.AssertionValue = encodedString
			return resultFilter, nil
		}
	default:
		return nil, fmt.Errorf("unsupported filter type: %T", resultFilter)
	}
}

func parseSubFilters(query string) ([]Filter, error) {
	var subFilters []Filter
	var currentFilter string
	var depth int

	for _, char := range query {
		if char == '(' {
			depth++
		} else if char == ')' {
			depth--
		}

		currentFilter += string(char)

		if depth == 0 {
			filter, err := QueryToFilter(currentFilter)
			if err != nil {
				return nil, err
			}
			subFilters = append(subFilters, filter)
			currentFilter = ""
		}
	}

	return subFilters, nil
}

func parseSubstringFilter(attributeDesc, assertionValue string) (Filter, error) {
	parts := strings.Split(assertionValue, "*")
	var substrings []SubstringFilter

	for i, part := range parts {
		if part == "" {
			continue
		}

		if i == 0 && !strings.HasPrefix(assertionValue, "*") {
			substrings = append(substrings, SubstringFilter{Initial: part})
		} else if i == len(parts)-1 && !strings.HasSuffix(assertionValue, "*") {
			substrings = append(substrings, SubstringFilter{Final: part})
		} else {
			substrings = append(substrings, SubstringFilter{Any: part})
		}
	}

	return &FilterSubstring{
		AttributeDesc: attributeDesc,
		Substrings:    substrings,
	}, nil
}

func ldapEscape(str string) string {
	str = strings.ReplaceAll(str, `\`, `\\`)
	str = strings.ReplaceAll(str, `(`, `\(`)
	str = strings.ReplaceAll(str, `)`, `\)`)
	return str
}
