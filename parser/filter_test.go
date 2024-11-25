package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		MatchValue:    "John Doe",
		DNAttributes:  true,
	}
	expectedQuery := "(cn:dn:=John Doe)"
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
