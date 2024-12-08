package parser

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
)

/*
	QueryToFilter Tests
*/

func TestQueryToFilter_And(t *testing.T) {
	query := "(&(cn=John Doe)(age>=25))"
	expectedFilter := &FilterAnd{
		Filters: []Filter{
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "John Doe",
			},
			&FilterGreaterOrEqual{
				AttributeDesc:  "age",
				AssertionValue: "25",
			},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Or(t *testing.T) {
	query := "(|(cn=John Doe)(cn=Jane Smith))"
	expectedFilter := &FilterOr{
		Filters: []Filter{
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "John Doe",
			},
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "Jane Smith",
			},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Not(t *testing.T) {
	query := "(!(cn=John Doe))"
	expectedFilter := &FilterNot{
		Filter: &FilterEqualityMatch{
			AttributeDesc:  "cn",
			AssertionValue: "John Doe",
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_EqualityMatch(t *testing.T) {
	query := "(cn=John Doe)"
	expectedFilter := &FilterEqualityMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John Doe",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring(t *testing.T) {
	query := "(cn=John*Doe)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Final: "Doe"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_GreaterOrEqual(t *testing.T) {
	query := "(age>=25)"
	expectedFilter := &FilterGreaterOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "25",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_LessOrEqual(t *testing.T) {
	query := "(age<=30)"
	expectedFilter := &FilterLessOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "30",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Present(t *testing.T) {
	query := "(cn=*)"
	expectedFilter := &FilterPresent{
		AttributeDesc: "cn",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_ApproxMatch(t *testing.T) {
	query := "(cn~=John)"
	expectedFilter := &FilterApproxMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_ExtensibleMatch(t *testing.T) {
	query := "(cn:caseExactMatch:=John Doe)"
	expectedFilter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_ExtensibleMatch_NoMatchingRule(t *testing.T) {
	query := "(cn:=John Doe)"
	expectedFilter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchValue:    "John Doe",
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_ExtensibleMatch_DNAttributes(t *testing.T) {
	query := "(cn:dn:=John Doe)"
	expectedFilter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_ExtensibleMatch_All(t *testing.T) {
	query := "(cn:dn:caseExactMatch:=John Doe)"
	expectedFilter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_MultipleAnyOnly(t *testing.T) {
	query := "(cn=*John*Smith*Doe*Jr*)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Any: "John"},
			{Any: "Smith"},
			{Any: "Doe"},
			{Any: "Jr"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_MultipleAnyNoFinal(t *testing.T) {
	query := "(cn=John*Smith*Doe*Jr*)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Any: "Smith"},
			{Any: "Doe"},
			{Any: "Jr"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_MultipleAnyNoInitial(t *testing.T) {
	query := "(cn=*John*Smith*Doe*Jr)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Any: "John"},
			{Any: "Smith"},
			{Any: "Doe"},
			{Final: "Jr"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_NoInitial(t *testing.T) {
	query := "(cn=*Doe)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Final: "Doe"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_NoFinal(t *testing.T) {
	query := "(cn=John*)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_InitialFinal(t *testing.T) {
	query := "(cn=John*Doe)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Final: "Doe"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_InitialAnyFinal(t *testing.T) {
	query := "(cn=John*Smith*Doe)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Any: "Smith"},
			{Final: "Doe"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Substring_InitialAnyAnyFinal(t *testing.T) {
	query := "(cn=John*Smith*Doe*Jr)"
	expectedFilter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Any: "Smith"},
			{Any: "Doe"},
			{Final: "Jr"},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

func TestQueryToFilter_Complex(t *testing.T) {
	query := "(&(|(cn=John*)(sn=Doe))(age>=25)(!(email=*example.com)))"
	expectedFilter := &FilterAnd{
		Filters: []Filter{
			&FilterOr{
				Filters: []Filter{
					&FilterSubstring{
						AttributeDesc: "cn",
						Substrings: []SubstringFilter{
							{Initial: "John"},
						},
					},
					&FilterEqualityMatch{
						AttributeDesc:  "sn",
						AssertionValue: "Doe",
					},
				},
			},
			&FilterGreaterOrEqual{
				AttributeDesc:  "age",
				AssertionValue: "25",
			},
			&FilterNot{
				Filter: &FilterSubstring{
					AttributeDesc: "email",
					Substrings: []SubstringFilter{
						{Final: "example.com"},
					},
				},
			},
		},
	}
	filter, err := QueryToFilter(query)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}

/*
	FilterToQuery Tests
*/

func TestFilterToQuery_And(t *testing.T) {
	filter := &FilterAnd{
		Filters: []Filter{
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "John Doe",
			},
			&FilterGreaterOrEqual{
				AttributeDesc:  "age",
				AssertionValue: "25",
			},
		},
	}
	expectedQuery := "(&(cn=John Doe)(age>=25))"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_Or(t *testing.T) {
	filter := &FilterOr{
		Filters: []Filter{
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "John Doe",
			},
			&FilterEqualityMatch{
				AttributeDesc:  "cn",
				AssertionValue: "Jane Smith",
			},
		},
	}
	expectedQuery := "(|(cn=John Doe)(cn=Jane Smith))"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_Not(t *testing.T) {
	filter := &FilterNot{
		Filter: &FilterEqualityMatch{
			AttributeDesc:  "cn",
			AssertionValue: "John Doe",
		},
	}
	expectedQuery := "(!(cn=John Doe))"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_EqualityMatch(t *testing.T) {
	filter := &FilterEqualityMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John Doe",
	}
	expectedQuery := "(cn=John Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_Substring(t *testing.T) {
	filter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Final: "Doe"},
		},
	}
	expectedQuery := "(cn=John*Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_GreaterOrEqual(t *testing.T) {
	filter := &FilterGreaterOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "25",
	}
	expectedQuery := "(age>=25)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_LessOrEqual(t *testing.T) {
	filter := &FilterLessOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "30",
	}
	expectedQuery := "(age<=30)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_Present(t *testing.T) {
	filter := &FilterPresent{
		AttributeDesc: "cn",
	}
	expectedQuery := "(cn=*)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_ApproxMatch(t *testing.T) {
	filter := &FilterApproxMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John",
	}
	expectedQuery := "(cn~=John)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_ExtensibleMatch(t *testing.T) {
	filter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
	}
	expectedQuery := "(cn:caseExactMatch:=John Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_ExtensibleMatch_NoMatchingRule(t *testing.T) {
	filter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchValue:    "John Doe",
	}
	expectedQuery := "(cn:=John Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_ExtensibleMatch_DNAttributes(t *testing.T) {
	filter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "rule",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}
	expectedQuery := "(cn:dn:rule:=John Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_ExtensibleMatch_All(t *testing.T) {
	filter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}
	expectedQuery := "(cn:dn:caseExactMatch:=John Doe)"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

func TestFilterToQuery_Complex(t *testing.T) {
	filter := &FilterAnd{
		Filters: []Filter{
			&FilterOr{
				Filters: []Filter{
					&FilterSubstring{
						AttributeDesc: "cn",
						Substrings: []SubstringFilter{
							{Initial: "John"},
						},
					},
					&FilterEqualityMatch{
						AttributeDesc:  "sn",
						AssertionValue: "Doe",
					},
				},
			},
			&FilterGreaterOrEqual{
				AttributeDesc:  "age",
				AssertionValue: "25",
			},
			&FilterNot{
				Filter: &FilterSubstring{
					AttributeDesc: "email",
					Substrings: []SubstringFilter{
						{Final: "example.com"},
					},
				},
			},
		},
	}
	expectedQuery := "(&(|(cn=John*)(sn=Doe))(age>=25)(!(email=*example.com)))"
	query, err := FilterToQuery(filter)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuery, query)
}

/*
	PacketToFilter Tests
*/

func TestPacketToFilter_EqualityMatch(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x3, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "John Doe", "AssertionValue"))

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterEqualityMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John Doe",
	}, filter)
}

func TestPacketToFilter_Substrings(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x4, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	substrings := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
	substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x0, "John", "Initial"))
	substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, "Doe", "Final"))
	packet.AppendChild(substrings)

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Final: "Doe"},
		},
	}, filter)
}

func TestPacketToFilter_GreaterOrEqual(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x5, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "age", "AttributeDesc"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "25", "AssertionValue"))

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterGreaterOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "25",
	}, filter)
}

func TestPacketToFilter_LessOrEqual(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x6, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "age", "AttributeDesc"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "30", "AssertionValue"))

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterLessOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "30",
	}, filter)
}

func TestPacketToFilter_Present(t *testing.T) {
	packet := ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x7, "cn", "")

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterPresent{
		AttributeDesc: "cn",
	}, filter)
}

func TestPacketToFilter_ApproxMatch(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x8, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "John", "AssertionValue"))

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterApproxMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John",
	}, filter)
}

func TestPacketToFilter_ExtensibleMatch(t *testing.T) {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x9, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, 0x1, "caseExactMatch", "MatchingRule"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, 0x2, "cn", "AttributeDesc"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, 0x3, "John Doe", "MatchValue"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, 0x4, true, "DNAttributes"))

	filter, err := PacketToFilter(packet)
	assert.NoError(t, err)
	assert.Equal(t, &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}, filter)
}

/*
	FilterToPacket Tests
*/

func TestFilterToPacket_EqualityMatch(t *testing.T) {
	filter := &FilterEqualityMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John Doe",
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x3, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "John Doe", "AssertionValue"))

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_Substrings(t *testing.T) {
	filter := &FilterSubstring{
		AttributeDesc: "cn",
		Substrings: []SubstringFilter{
			{Initial: "John"},
			{Final: "Doe"},
		},
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x4, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	substrings := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
	substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x0, "John", "Initial"))
	substrings.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, "Doe", "Final"))
	expectedPacket.AppendChild(substrings)

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_GreaterOrEqual(t *testing.T) {
	filter := &FilterGreaterOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "25",
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x5, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "age", "AttributeDesc"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "25", "AssertionValue"))

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_LessOrEqual(t *testing.T) {
	filter := &FilterLessOrEqual{
		AttributeDesc:  "age",
		AssertionValue: "30",
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x6, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "age", "AttributeDesc"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "30", "AssertionValue"))

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_Present(t *testing.T) {
	filter := &FilterPresent{
		AttributeDesc: "cn",
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x7, "cn", "")
	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_ApproxMatch(t *testing.T) {
	filter := &FilterApproxMatch{
		AttributeDesc:  "cn",
		AssertionValue: "John",
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x8, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeDesc"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "John", "AssertionValue"))

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

func TestFilterToPacket_ExtensibleMatch(t *testing.T) {
	filter := &FilterExtensibleMatch{
		AttributeDesc: "cn",
		MatchingRule:  "caseExactMatch",
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}

	packet := FilterToPacket(filter)

	expectedPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x9, nil, "")
	expectedPacket.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x1, "caseExactMatch", "MatchingRule"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x2, "cn", "AttributeDesc"))
	expectedPacket.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x3, "John Doe", "MatchValue"))
	expectedPacket.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, 0x4, true, "DNAttributes"))

	assert.Equal(t, expectedPacket.Bytes(), packet.Bytes())
}

// TODO: Add more tests for edge cases of FilterToQuery, FilterToPacket, and PacketToFilter

/*
func TestQueryToFilter_InvalidFilter(t *testing.T) {
	testCases := []struct {
		name  string
		query string
	}{
		{
			name:  "Empty filter",
			query: "",
		},
		{
			name:  "Missing opening parenthesis",
			query: "cn=John Doe)",
		},
		{
			name:  "Missing closing parenthesis",
			query: "(cn=John Doe",
		},
		{
			name:  "Invalid filter format",
			query: "cn~John Doe",
		},
		{
			name:  "Invalid AND filter",
			query: "(&(cn=John)(sn=Doe)",
		},
		{
			name:  "Invalid OR filter",
			query: "(|(cn=John(sn=Doe))",
		},
		{
			name:  "Invalid NOT filter",
			query: "(!(cn=John)(sn=Doe))",
		},
		{
			name:  "Invalid attribute description",
			query: "(invalid attribute=John Doe)",
		},
		{
			name:  "Missing assertion value",
			query: "(cn=)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := QueryToFilter(tc.query)
			assert.Error(t, err, "Expected an error for invalid filter")
		})
	}
}
*/
