// Code generated by ent, DO NOT EDIT.

package test

import (
	"ct_oval_tool/pkg/ent/predicate"

	"entgo.io/ent/dialect/sql"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Test {
	return predicate.Test(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Test {
	return predicate.Test(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.Test {
	return predicate.Test(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.Test {
	return predicate.Test(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Test {
	return predicate.Test(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Test {
	return predicate.Test(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Test {
	return predicate.Test(sql.FieldLTE(FieldID, id))
}

// TestID applies equality check predicate on the "test_id" field. It's identical to TestIDEQ.
func TestID(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldTestID, v))
}

// Comment applies equality check predicate on the "comment" field. It's identical to CommentEQ.
func Comment(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldComment, v))
}

// ObjectID applies equality check predicate on the "object_id" field. It's identical to ObjectIDEQ.
func ObjectID(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldObjectID, v))
}

// StateID applies equality check predicate on the "state_id" field. It's identical to StateIDEQ.
func StateID(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldStateID, v))
}

// TestIDEQ applies the EQ predicate on the "test_id" field.
func TestIDEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldTestID, v))
}

// TestIDNEQ applies the NEQ predicate on the "test_id" field.
func TestIDNEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldNEQ(FieldTestID, v))
}

// TestIDIn applies the In predicate on the "test_id" field.
func TestIDIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldIn(FieldTestID, vs...))
}

// TestIDNotIn applies the NotIn predicate on the "test_id" field.
func TestIDNotIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldNotIn(FieldTestID, vs...))
}

// TestIDGT applies the GT predicate on the "test_id" field.
func TestIDGT(v string) predicate.Test {
	return predicate.Test(sql.FieldGT(FieldTestID, v))
}

// TestIDGTE applies the GTE predicate on the "test_id" field.
func TestIDGTE(v string) predicate.Test {
	return predicate.Test(sql.FieldGTE(FieldTestID, v))
}

// TestIDLT applies the LT predicate on the "test_id" field.
func TestIDLT(v string) predicate.Test {
	return predicate.Test(sql.FieldLT(FieldTestID, v))
}

// TestIDLTE applies the LTE predicate on the "test_id" field.
func TestIDLTE(v string) predicate.Test {
	return predicate.Test(sql.FieldLTE(FieldTestID, v))
}

// TestIDContains applies the Contains predicate on the "test_id" field.
func TestIDContains(v string) predicate.Test {
	return predicate.Test(sql.FieldContains(FieldTestID, v))
}

// TestIDHasPrefix applies the HasPrefix predicate on the "test_id" field.
func TestIDHasPrefix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasPrefix(FieldTestID, v))
}

// TestIDHasSuffix applies the HasSuffix predicate on the "test_id" field.
func TestIDHasSuffix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasSuffix(FieldTestID, v))
}

// TestIDEqualFold applies the EqualFold predicate on the "test_id" field.
func TestIDEqualFold(v string) predicate.Test {
	return predicate.Test(sql.FieldEqualFold(FieldTestID, v))
}

// TestIDContainsFold applies the ContainsFold predicate on the "test_id" field.
func TestIDContainsFold(v string) predicate.Test {
	return predicate.Test(sql.FieldContainsFold(FieldTestID, v))
}

// CommentEQ applies the EQ predicate on the "comment" field.
func CommentEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldComment, v))
}

// CommentNEQ applies the NEQ predicate on the "comment" field.
func CommentNEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldNEQ(FieldComment, v))
}

// CommentIn applies the In predicate on the "comment" field.
func CommentIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldIn(FieldComment, vs...))
}

// CommentNotIn applies the NotIn predicate on the "comment" field.
func CommentNotIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldNotIn(FieldComment, vs...))
}

// CommentGT applies the GT predicate on the "comment" field.
func CommentGT(v string) predicate.Test {
	return predicate.Test(sql.FieldGT(FieldComment, v))
}

// CommentGTE applies the GTE predicate on the "comment" field.
func CommentGTE(v string) predicate.Test {
	return predicate.Test(sql.FieldGTE(FieldComment, v))
}

// CommentLT applies the LT predicate on the "comment" field.
func CommentLT(v string) predicate.Test {
	return predicate.Test(sql.FieldLT(FieldComment, v))
}

// CommentLTE applies the LTE predicate on the "comment" field.
func CommentLTE(v string) predicate.Test {
	return predicate.Test(sql.FieldLTE(FieldComment, v))
}

// CommentContains applies the Contains predicate on the "comment" field.
func CommentContains(v string) predicate.Test {
	return predicate.Test(sql.FieldContains(FieldComment, v))
}

// CommentHasPrefix applies the HasPrefix predicate on the "comment" field.
func CommentHasPrefix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasPrefix(FieldComment, v))
}

// CommentHasSuffix applies the HasSuffix predicate on the "comment" field.
func CommentHasSuffix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasSuffix(FieldComment, v))
}

// CommentEqualFold applies the EqualFold predicate on the "comment" field.
func CommentEqualFold(v string) predicate.Test {
	return predicate.Test(sql.FieldEqualFold(FieldComment, v))
}

// CommentContainsFold applies the ContainsFold predicate on the "comment" field.
func CommentContainsFold(v string) predicate.Test {
	return predicate.Test(sql.FieldContainsFold(FieldComment, v))
}

// ObjectIDEQ applies the EQ predicate on the "object_id" field.
func ObjectIDEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldObjectID, v))
}

// ObjectIDNEQ applies the NEQ predicate on the "object_id" field.
func ObjectIDNEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldNEQ(FieldObjectID, v))
}

// ObjectIDIn applies the In predicate on the "object_id" field.
func ObjectIDIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldIn(FieldObjectID, vs...))
}

// ObjectIDNotIn applies the NotIn predicate on the "object_id" field.
func ObjectIDNotIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldNotIn(FieldObjectID, vs...))
}

// ObjectIDGT applies the GT predicate on the "object_id" field.
func ObjectIDGT(v string) predicate.Test {
	return predicate.Test(sql.FieldGT(FieldObjectID, v))
}

// ObjectIDGTE applies the GTE predicate on the "object_id" field.
func ObjectIDGTE(v string) predicate.Test {
	return predicate.Test(sql.FieldGTE(FieldObjectID, v))
}

// ObjectIDLT applies the LT predicate on the "object_id" field.
func ObjectIDLT(v string) predicate.Test {
	return predicate.Test(sql.FieldLT(FieldObjectID, v))
}

// ObjectIDLTE applies the LTE predicate on the "object_id" field.
func ObjectIDLTE(v string) predicate.Test {
	return predicate.Test(sql.FieldLTE(FieldObjectID, v))
}

// ObjectIDContains applies the Contains predicate on the "object_id" field.
func ObjectIDContains(v string) predicate.Test {
	return predicate.Test(sql.FieldContains(FieldObjectID, v))
}

// ObjectIDHasPrefix applies the HasPrefix predicate on the "object_id" field.
func ObjectIDHasPrefix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasPrefix(FieldObjectID, v))
}

// ObjectIDHasSuffix applies the HasSuffix predicate on the "object_id" field.
func ObjectIDHasSuffix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasSuffix(FieldObjectID, v))
}

// ObjectIDEqualFold applies the EqualFold predicate on the "object_id" field.
func ObjectIDEqualFold(v string) predicate.Test {
	return predicate.Test(sql.FieldEqualFold(FieldObjectID, v))
}

// ObjectIDContainsFold applies the ContainsFold predicate on the "object_id" field.
func ObjectIDContainsFold(v string) predicate.Test {
	return predicate.Test(sql.FieldContainsFold(FieldObjectID, v))
}

// StateIDEQ applies the EQ predicate on the "state_id" field.
func StateIDEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldEQ(FieldStateID, v))
}

// StateIDNEQ applies the NEQ predicate on the "state_id" field.
func StateIDNEQ(v string) predicate.Test {
	return predicate.Test(sql.FieldNEQ(FieldStateID, v))
}

// StateIDIn applies the In predicate on the "state_id" field.
func StateIDIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldIn(FieldStateID, vs...))
}

// StateIDNotIn applies the NotIn predicate on the "state_id" field.
func StateIDNotIn(vs ...string) predicate.Test {
	return predicate.Test(sql.FieldNotIn(FieldStateID, vs...))
}

// StateIDGT applies the GT predicate on the "state_id" field.
func StateIDGT(v string) predicate.Test {
	return predicate.Test(sql.FieldGT(FieldStateID, v))
}

// StateIDGTE applies the GTE predicate on the "state_id" field.
func StateIDGTE(v string) predicate.Test {
	return predicate.Test(sql.FieldGTE(FieldStateID, v))
}

// StateIDLT applies the LT predicate on the "state_id" field.
func StateIDLT(v string) predicate.Test {
	return predicate.Test(sql.FieldLT(FieldStateID, v))
}

// StateIDLTE applies the LTE predicate on the "state_id" field.
func StateIDLTE(v string) predicate.Test {
	return predicate.Test(sql.FieldLTE(FieldStateID, v))
}

// StateIDContains applies the Contains predicate on the "state_id" field.
func StateIDContains(v string) predicate.Test {
	return predicate.Test(sql.FieldContains(FieldStateID, v))
}

// StateIDHasPrefix applies the HasPrefix predicate on the "state_id" field.
func StateIDHasPrefix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasPrefix(FieldStateID, v))
}

// StateIDHasSuffix applies the HasSuffix predicate on the "state_id" field.
func StateIDHasSuffix(v string) predicate.Test {
	return predicate.Test(sql.FieldHasSuffix(FieldStateID, v))
}

// StateIDEqualFold applies the EqualFold predicate on the "state_id" field.
func StateIDEqualFold(v string) predicate.Test {
	return predicate.Test(sql.FieldEqualFold(FieldStateID, v))
}

// StateIDContainsFold applies the ContainsFold predicate on the "state_id" field.
func StateIDContainsFold(v string) predicate.Test {
	return predicate.Test(sql.FieldContainsFold(FieldStateID, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Test) predicate.Test {
	return predicate.Test(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Test) predicate.Test {
	return predicate.Test(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Test) predicate.Test {
	return predicate.Test(sql.NotPredicates(p))
}
