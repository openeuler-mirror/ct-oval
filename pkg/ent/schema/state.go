package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type State struct {
	ent.Schema
}

func (State) Fields() []ent.Field {
	return []ent.Field{
		field.String("state_id"),
		field.String("value"),
		field.String("tag"),
		field.String("datatype"),
		field.String("operation"),
	}
}

func (State) Index() []ent.Index {
	return []ent.Index{
		index.Fields("state_id").Unique(),
	}
}
