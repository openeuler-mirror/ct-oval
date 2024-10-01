package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Test struct {
	ent.Schema
}

func (Test) Fields() []ent.Field {
	return []ent.Field{
		field.String("test_id"),
		field.String("comment"),
		field.String("object_id"),
		field.String("state_id"),
	}
}

func (Test) Index() []ent.Index {
	return []ent.Index{
		index.Fields("test_id").Unique(),
	}
}
