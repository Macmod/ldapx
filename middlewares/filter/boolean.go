package filtermid

import (
	"math/rand"

	"github.com/Macmod/ldapx/parser"
)

/*
	Boolean FilterMiddlewares

	References:
	- DEFCON32 - MaLDAPtive
	- Microsoft Open Specifications - MS-ADTS
	  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
*/

func RandAddBoolFilterObf(maxDepth int, prob float32) func(f parser.Filter) parser.Filter {
	return func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float32() < prob {
				if rand.Intn(2) == 0 {
					// Wrap in AND
					result = &parser.FilterAnd{
						Filters: []parser.Filter{result},
					}
				} else {
					// Wrap in OR
					result = &parser.FilterOr{
						Filters: []parser.Filter{result},
					}
				}
			}
		}

		return result
	}
}

func RandDblNegBoolFilterObf(maxDepth int, prob float32) func(f parser.Filter) parser.Filter {
	return LeafApplierFilterMiddleware(func(f parser.Filter) parser.Filter {
		depth := rand.Intn(maxDepth) + 1
		result := f

		for i := 0; i < depth; i++ {
			if rand.Float32() < prob {
				// Wrap in NOTs
				result = &parser.FilterNot{
					Filter: &parser.FilterNot{
						Filter: result,
					},
				}
			}
		}

		return result
	})
}

func RandDeMorganBoolFilterObf(prob float32) func(f parser.Filter) parser.Filter {
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		// TODO: Review
		case *parser.FilterAnd:
			// Apply DeMorgan with prob X
			if rand.Float32() < prob {
				// Convert AND to OR using DeMorgan: !(a && b) = !a || !b
				notFilters := make([]parser.Filter, len(f.Filters))
				for i, subFilter := range f.Filters {
					notFilters[i] = &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(subFilter)}
				}
				return &parser.FilterNot{Filter: &parser.FilterOr{Filters: notFilters}}
			}

			// Just recurse on children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandDeMorganBoolFilterObf(prob)(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			// Apply DeMorgan with prob X
			if rand.Float32() < prob {
				// Convert OR to AND using DeMorgan: !(a || b) = !a && !b
				notFilters := make([]parser.Filter, len(f.Filters))
				for i, subFilter := range f.Filters {
					notFilters[i] = &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(subFilter)}
				}
				return &parser.FilterNot{Filter: &parser.FilterAnd{Filters: notFilters}}
			}

			// Just recurse on children
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = RandDeMorganBoolFilterObf(prob)(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: RandDeMorganBoolFilterObf(prob)(f.Filter)}

		default:
			return filter
		}
	}
}

func RandBoolReorderFilterObf() func(f parser.Filter) parser.Filter {
	return func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			// Create new slice and copy filters
			newFilters := make([]parser.Filter, len(f.Filters))
			copy(newFilters, f.Filters)

			// Fisher-Yates shuffle
			for i := len(newFilters) - 1; i > 0; i-- {
				j := rand.Intn(i + 1)
				newFilters[i], newFilters[j] = newFilters[j], newFilters[i]
			}

			// Recurse on children
			for i, subFilter := range newFilters {
				newFilters[i] = RandBoolReorderFilterObf()(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			// Create new slice and copy filters
			newFilters := make([]parser.Filter, len(f.Filters))
			copy(newFilters, f.Filters)

			// Fisher-Yates shuffle
			for i := len(newFilters) - 1; i > 0; i-- {
				j := rand.Intn(i + 1)
				newFilters[i], newFilters[j] = newFilters[j], newFilters[i]
			}

			// Recurse on children
			for i, subFilter := range newFilters {
				newFilters[i] = RandBoolReorderFilterObf()(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: RandBoolReorderFilterObf()(f.Filter)}

		default:
			return filter
		}
	}
}
