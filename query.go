package warehouse

import (
	"encoding/json"
	"fmt"
)

type KeyExistsQuery struct {
	Key string
}

func NewKeyExistsQuery(key string) *KeyExistsQuery {
	return &KeyExistsQuery{Key: key}
}

func (KeyExistsQuery) isQuery() {}

func (q *KeyExistsQuery) MarshalJSON() ([]byte, error) {
	var v struct {
		KeyExists string `json:"key_exists"`
	}

	v.KeyExists = q.Key

	return json.Marshal(v)
}

type StrInListQuery struct {
	Key    string
	Values []string
}

func NewStrInListQuery(key string, values []string) *StrInListQuery {
	return &StrInListQuery{Key: key, Values: values}
}

func (StrInListQuery) isQuery() {}

func (q *StrInListQuery) MarshalJSON() ([]byte, error) {
	var v struct {
		StrInListQuery struct {
			Key    string   `json:"key"`
			Values []string `json:"values"`
		} `json:"str_in_list"`
	}

	v.StrInListQuery.Key = q.Key
	v.StrInListQuery.Values = q.Values

	return json.Marshal(v)
}

type EqualsQuery struct {
	Key   string
	Value interface{}
}

func NewEqualsQuery(key, value string) *EqualsQuery {
	return &EqualsQuery{Key: key, Value: value}
}

func (EqualsQuery) isQuery() {}

func (q *EqualsQuery) MarshalJSON() ([]byte, error) {
	var v struct {
		EqualsQuery struct {
			Key   string      `json:"key"`
			Value interface{} `json:"value"`
		} `json:"equals"`
	}

	v.EqualsQuery.Key = q.Key
	v.EqualsQuery.Value = q.Value

	return json.Marshal(v)
}

type NotQuery struct {
	Child Query
}

func NewNotQuery(child Query) *NotQuery {
	return &NotQuery{Child: child}
}

func (NotQuery) isQuery() {}

func (n *NotQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Not Query `json:"Not"`
	}{
		Not: n.Child,
	})
}

type OrQuery struct {
	Children []Query
}

func NewOrQuery(children []Query) *OrQuery {
	return &OrQuery{Children: children}
}

func (OrQuery) isQuery() {}

func (n *OrQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Or []Query `json:"or"`
	}{
		Or: n.Children,
	})
}

type AndQuery struct {
	Children []Query
}

func (AndQuery) isQuery() {}

func (n *AndQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And []Query `json:"and"`
	}{
		And: n.Children,
	})
}

func NewAndQuery(children []Query) *AndQuery {
	return &AndQuery{Children: children}
}

type NaturalQuery struct {
	Query string
}

func (NaturalQuery) isQuery() {}

func (n *NaturalQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NaturalQuery string `json:"natural_query"`
	}{
		NaturalQuery: n.Query,
	})
}

func NewNaturalQuery(q string) *NaturalQuery {
	return &NaturalQuery{Query: q}
}

type Query interface {
	MarshalJSON() ([]byte, error)
	isQuery()
}

type SortOrder int

const (
	SortOrderNone SortOrder = iota
	SortOrderAscending
	SortOrderDescending
)

func (s SortOrder) MarshalText() ([]byte, error) {
	switch s {
	case SortOrderAscending:
		return []byte(`ascending`), nil
	case SortOrderDescending:
		return []byte(`descending`), nil
	default:
		return nil, fmt.Errorf("invalid sort order")
	}
}

type SortType int

const (
	SortTypeNone SortType = iota
	SortTypeAlphanumerical
	SortTypeNatural
	SortTypeChronological
	SortTypeChronologicalModification
)

func (s SortType) MarshalText() ([]byte, error) {
	switch s {
	case SortTypeAlphanumerical:
		return []byte(`alphanumerical`), nil
	case SortTypeNatural:
		return []byte(`natural`), nil
	case SortTypeChronological:
		return []byte(`chronological`), nil
	case SortTypeChronologicalModification:
		return []byte(`chronologicalModification`), nil
	default:
		return nil, fmt.Errorf("invalid sort type")
	}
}

type Sorting struct {
	Sort  SortType  `json:"sort,omitempty"`
	Order SortOrder `json:"order,omitempty"`
	Key   string    `json:"key,omitempty"`
}

type KeySearch struct {
	Table          string   `json:"table"`
	Keys           []string `json:"keys"`
	Limit          int      `json:"limit,omitempty"`
	Query          Query    `json:"query"`
	Sorting        Sorting  `json:"sorting,omitempty"`
	Distinct       bool     `json:"distinct"`
	IncludeGarbage bool     `json:"includeGarbage"`
}
