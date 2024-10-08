package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Cveref struct {
	ent.Schema
}

func (Cveref) Fields() []ent.Field {
	return []ent.Field{
		field.String("ref_id"),
		field.String("ref_url"),
	}
}

func (Cveref) Index() []ent.Index {
	return []ent.Index{
		index.Fields("ref_id").Unique(),
	}
}
