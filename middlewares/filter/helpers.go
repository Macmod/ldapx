package filtermid

import "github.com/Macmod/ldapx/parser"

func LeafApplierFilterMiddleware(fm FilterMiddleware) FilterMiddleware {
	var applier FilterMiddleware
	applier = func(filter parser.Filter) parser.Filter {
		switch f := filter.(type) {
		case *parser.FilterAnd:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterAnd{Filters: newFilters}

		case *parser.FilterOr:
			newFilters := make([]parser.Filter, len(f.Filters))
			for i, subFilter := range f.Filters {
				newFilters[i] = applier(subFilter)
			}
			return &parser.FilterOr{Filters: newFilters}

		case *parser.FilterNot:
			return &parser.FilterNot{Filter: applier(f.Filter)}

		default:
			return fm(filter)
		}
	}

	return applier
}
