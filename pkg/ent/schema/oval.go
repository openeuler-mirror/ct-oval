package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Oval struct {
	ent.Schema
}

func (Oval) Fields() []ent.Field {
	return []ent.Field{
		field.String("productname"),
		field.String("productversion"),
		field.String("schemaversion"),
		field.String("ovalversion"),
		field.String("class"),
		field.String("family"),
		field.String("copyright"),
		field.String("timestamp"),
		field.String("id").Unique(),
		field.String("title"),
		field.String("description"),
		field.String("severity"),
		field.String("issuedate"),
		field.String("platform"),
		field.String("arch_list").Default(""),
		field.String("cve_list").Default(""),
		field.String("test_list").Default(""),
		field.String("object_list").Default(""),
		field.String("state_list").Default(""),
	}
}

func (Oval) Index() []ent.Index {
	return []ent.Index{
		index.Fields("id").Unique(),
	}
}
