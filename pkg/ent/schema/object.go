package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Object struct {
	ent.Schema
}

func (Object) Fields() []ent.Field {
	return []ent.Field{
		field.String("object_id"),
		field.String("name"),
	}
}

func (Object) Index() []ent.Index {
	return []ent.Index{
		index.Fields("object_id").Unique(),
	}
}
