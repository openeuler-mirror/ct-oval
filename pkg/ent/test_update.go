// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/predicate"
	"ct_oval_tool/pkg/ent/test"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// TestUpdate is the builder for updating Test entities.
type TestUpdate struct {
	config
	hooks    []Hook
	mutation *TestMutation
}

// Where appends a list predicates to the TestUpdate builder.
func (tu *TestUpdate) Where(ps ...predicate.Test) *TestUpdate {
	tu.mutation.Where(ps...)
	return tu
}

// SetTestID sets the "test_id" field.
func (tu *TestUpdate) SetTestID(s string) *TestUpdate {
	tu.mutation.SetTestID(s)
	return tu
}

// SetNillableTestID sets the "test_id" field if the given value is not nil.
func (tu *TestUpdate) SetNillableTestID(s *string) *TestUpdate {
	if s != nil {
		tu.SetTestID(*s)
	}
	return tu
}

// SetComment sets the "comment" field.
func (tu *TestUpdate) SetComment(s string) *TestUpdate {
	tu.mutation.SetComment(s)
	return tu
}

// SetNillableComment sets the "comment" field if the given value is not nil.
func (tu *TestUpdate) SetNillableComment(s *string) *TestUpdate {
	if s != nil {
		tu.SetComment(*s)
	}
	return tu
}

// SetObjectID sets the "object_id" field.
func (tu *TestUpdate) SetObjectID(s string) *TestUpdate {
	tu.mutation.SetObjectID(s)
	return tu
}

// SetNillableObjectID sets the "object_id" field if the given value is not nil.
func (tu *TestUpdate) SetNillableObjectID(s *string) *TestUpdate {
	if s != nil {
		tu.SetObjectID(*s)
	}
	return tu
}

// SetStateID sets the "state_id" field.
func (tu *TestUpdate) SetStateID(s string) *TestUpdate {
	tu.mutation.SetStateID(s)
	return tu
}

// SetNillableStateID sets the "state_id" field if the given value is not nil.
func (tu *TestUpdate) SetNillableStateID(s *string) *TestUpdate {
	if s != nil {
		tu.SetStateID(*s)
	}
	return tu
}

// Mutation returns the TestMutation object of the builder.
func (tu *TestUpdate) Mutation() *TestMutation {
	return tu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (tu *TestUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, tu.sqlSave, tu.mutation, tu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tu *TestUpdate) SaveX(ctx context.Context) int {
	affected, err := tu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (tu *TestUpdate) Exec(ctx context.Context) error {
	_, err := tu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tu *TestUpdate) ExecX(ctx context.Context) {
	if err := tu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (tu *TestUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(test.Table, test.Columns, sqlgraph.NewFieldSpec(test.FieldID, field.TypeInt))
	if ps := tu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tu.mutation.TestID(); ok {
		_spec.SetField(test.FieldTestID, field.TypeString, value)
	}
	if value, ok := tu.mutation.Comment(); ok {
		_spec.SetField(test.FieldComment, field.TypeString, value)
	}
	if value, ok := tu.mutation.ObjectID(); ok {
		_spec.SetField(test.FieldObjectID, field.TypeString, value)
	}
	if value, ok := tu.mutation.StateID(); ok {
		_spec.SetField(test.FieldStateID, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, tu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{test.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	tu.mutation.done = true
	return n, nil
}

// TestUpdateOne is the builder for updating a single Test entity.
type TestUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *TestMutation
}

// SetTestID sets the "test_id" field.
func (tuo *TestUpdateOne) SetTestID(s string) *TestUpdateOne {
	tuo.mutation.SetTestID(s)
	return tuo
}

// SetNillableTestID sets the "test_id" field if the given value is not nil.
func (tuo *TestUpdateOne) SetNillableTestID(s *string) *TestUpdateOne {
	if s != nil {
		tuo.SetTestID(*s)
	}
	return tuo
}

// SetComment sets the "comment" field.
func (tuo *TestUpdateOne) SetComment(s string) *TestUpdateOne {
	tuo.mutation.SetComment(s)
	return tuo
}

// SetNillableComment sets the "comment" field if the given value is not nil.
func (tuo *TestUpdateOne) SetNillableComment(s *string) *TestUpdateOne {
	if s != nil {
		tuo.SetComment(*s)
	}
	return tuo
}

// SetObjectID sets the "object_id" field.
func (tuo *TestUpdateOne) SetObjectID(s string) *TestUpdateOne {
	tuo.mutation.SetObjectID(s)
	return tuo
}

// SetNillableObjectID sets the "object_id" field if the given value is not nil.
func (tuo *TestUpdateOne) SetNillableObjectID(s *string) *TestUpdateOne {
	if s != nil {
		tuo.SetObjectID(*s)
	}
	return tuo
}

// SetStateID sets the "state_id" field.
func (tuo *TestUpdateOne) SetStateID(s string) *TestUpdateOne {
	tuo.mutation.SetStateID(s)
	return tuo
}

// SetNillableStateID sets the "state_id" field if the given value is not nil.
func (tuo *TestUpdateOne) SetNillableStateID(s *string) *TestUpdateOne {
	if s != nil {
		tuo.SetStateID(*s)
	}
	return tuo
}

// Mutation returns the TestMutation object of the builder.
func (tuo *TestUpdateOne) Mutation() *TestMutation {
	return tuo.mutation
}

// Where appends a list predicates to the TestUpdate builder.
func (tuo *TestUpdateOne) Where(ps ...predicate.Test) *TestUpdateOne {
	tuo.mutation.Where(ps...)
	return tuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (tuo *TestUpdateOne) Select(field string, fields ...string) *TestUpdateOne {
	tuo.fields = append([]string{field}, fields...)
	return tuo
}

// Save executes the query and returns the updated Test entity.
func (tuo *TestUpdateOne) Save(ctx context.Context) (*Test, error) {
	return withHooks(ctx, tuo.sqlSave, tuo.mutation, tuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tuo *TestUpdateOne) SaveX(ctx context.Context) *Test {
	node, err := tuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (tuo *TestUpdateOne) Exec(ctx context.Context) error {
	_, err := tuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tuo *TestUpdateOne) ExecX(ctx context.Context) {
	if err := tuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (tuo *TestUpdateOne) sqlSave(ctx context.Context) (_node *Test, err error) {
	_spec := sqlgraph.NewUpdateSpec(test.Table, test.Columns, sqlgraph.NewFieldSpec(test.FieldID, field.TypeInt))
	id, ok := tuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Test.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := tuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, test.FieldID)
		for _, f := range fields {
			if !test.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != test.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := tuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tuo.mutation.TestID(); ok {
		_spec.SetField(test.FieldTestID, field.TypeString, value)
	}
	if value, ok := tuo.mutation.Comment(); ok {
		_spec.SetField(test.FieldComment, field.TypeString, value)
	}
	if value, ok := tuo.mutation.ObjectID(); ok {
		_spec.SetField(test.FieldObjectID, field.TypeString, value)
	}
	if value, ok := tuo.mutation.StateID(); ok {
		_spec.SetField(test.FieldStateID, field.TypeString, value)
	}
	_node = &Test{config: tuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, tuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{test.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	tuo.mutation.done = true
	return _node, nil
}
