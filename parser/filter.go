package parser

import (
	"fmt"
	"strings"

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
type SubstringFilter struct {
	Initial string
	Any     []string
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
		attr := string(packet.Children[0].ByteValue)
		value := string(packet.Children[1].ByteValue)
		return &FilterEqualityMatch{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x4: // Substring filter (e.g., (cn=Jo*hn))
		if len(packet.Children) < 2 {
			return nil, fmt.Errorf("Substring filter should have at least 2 children")
		}

		attr := string(packet.Children[0].ByteValue)
		var substrs []SubstringFilter
		for _, subPacket := range packet.Children[1].Children {
			switch int(subPacket.Tag) {
			case 0x0: // Initial
				substrs = append(substrs, SubstringFilter{Initial: string(subPacket.Data.Bytes())})
			case 0x1: // Any
				substrs = append(substrs, SubstringFilter{Any: []string{string(subPacket.Data.Bytes())}})
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
		attr := string(packet.Children[0].ByteValue)
		value := string(packet.Children[1].ByteValue)
		return &FilterGreaterOrEqual{
			AttributeDesc:  attr,
			AssertionValue: value,
		}, nil

	case 0x6: // LessOrEqual filter (e.g., (age<=30))
		if len(packet.Children) != 2 {
			return nil, fmt.Errorf("LessOrEqual filter should have 2 children")
		}
		attr := string(packet.Children[0].ByteValue)
		value := string(packet.Children[1].ByteValue)
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
		attr := string(packet.Children[0].ByteValue)
		value := string(packet.Children[1].ByteValue)
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
			for i, any := range sub.Any {
				result.WriteString(fmt.Sprintf("%s  Any[%d]: %s\n", indent, i, any))
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

// TODO: Review
func FilterToPacket(f Filter) *ber.Packet {
	switch filter := f.(type) {
	case *FilterAnd:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x0, nil, "AND")
		for _, subFilter := range filter.Filters {
			packet.AppendChild(FilterToPacket(subFilter))
		}
		return packet

	case *FilterOr:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x1, nil, "OR")
		for _, subFilter := range filter.Filters {
			packet.AppendChild(FilterToPacket(subFilter))
		}
		return packet

	case *FilterNot:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x2, nil, "NOT")
		packet.AppendChild(FilterToPacket(filter.Filter))
		return packet

	case *FilterEqualityMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x3, nil, "Equality Match")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, "Attribute Desc"))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, "Assertion Value"))
		return packet

	case *FilterSubstring:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x4, nil, "Substring")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, "Attribute Desc"))

		substrings := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
		for _, substr := range filter.Substrings {
			if substr.Initial != "" {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x0, substr.Initial, "Initial"))
			}
			for _, any := range substr.Any {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x1, any, "Any"))
			}
			if substr.Final != "" {
				substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, substr.Final, "Final"))
			}
		}
		packet.AppendChild(substrings)
		return packet

	case *FilterGreaterOrEqual:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x5, nil, "Greater Or Equal")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, "Attribute Desc"))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, "Assertion Value"))
		return packet

	case *FilterLessOrEqual:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x6, nil, "Less Or Equal")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, "Attribute Desc"))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, "Assertion Value"))
		return packet

	case *FilterPresent:
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x7, filter.AttributeDesc, "Present")

	case *FilterApproxMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x8, nil, "Approx Match")
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AttributeDesc, "Attribute Desc"))
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, filter.AssertionValue, "Assertion Value"))
		return packet

	case *FilterExtensibleMatch:
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x9, nil, "Extensible Match")
		if filter.MatchingRule != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x1, filter.MatchingRule, "Matching Rule"))
		}
		if filter.AttributeDesc != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, filter.AttributeDesc, "Attribute Desc"))
		}
		if filter.MatchValue != "" {
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x3, filter.MatchValue, "Match Value"))
		}
		if filter.DNAttributes {
			packet.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, 0x4, true, "DN Attributes"))
		}
		return packet
	}

	return nil
}
