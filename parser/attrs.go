package parser

type Attribute struct {
	Name   string
	Values []string
}

type AttrEntries []Attribute

func (a *AttrEntries) AddValue(name string, value string) {
	if len(*a) == 0 {
		*a = make([]Attribute, 0)
	}

	for i := range *a {
		if (*a)[i].Name == name {
			(*a)[i].Values = append((*a)[i].Values, value)
			return
		}
	}

	*a = append(*a, Attribute{Name: name, Values: []string{value}})
}

func (a *AttrEntries) AppendAttr(name string, value string) {
	*a = append(*a, Attribute{Name: name, Values: []string{value}})
}
