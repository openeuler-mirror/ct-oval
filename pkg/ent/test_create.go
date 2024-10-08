// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/test"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// TestCreate is the builder for creating a Test entity.
type TestCreate struct {
	config
	mutation *TestMutation
	hooks    []Hook
}

// SetTestID sets the "test_id" field.
func (tc *TestCreate) SetTestID(s string) *TestCreate {
	tc.mutation.SetTestID(s)
	return tc
}

// SetComment sets the "comment" field.
func (tc *TestCreate) SetComment(s string) *TestCreate {
	tc.mutation.SetComment(s)
	return tc
}

// SetObjectID sets the "object_id" field.
func (tc *TestCreate) SetObjectID(s string) *TestCreate {
	tc.mutation.SetObjectID(s)
	return tc
}

// SetStateID sets the "state_id" field.
func (tc *TestCreate) SetStateID(s string) *TestCreate {
	tc.mutation.SetStateID(s)
	return tc
}

// Mutation returns the TestMutation object of the builder.
func (tc *TestCreate) Mutation() *TestMutation {
	return tc.mutation
}

// Save creates the Test in the database.
func (tc *TestCreate) Save(ctx context.Context) (*Test, error) {
	return withHooks(ctx, tc.sqlSave, tc.mutation, tc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (tc *TestCreate) SaveX(ctx context.Context) *Test {
	v, err := tc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tc *TestCreate) Exec(ctx context.Context) error {
	_, err := tc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tc *TestCreate) ExecX(ctx context.Context) {
	if err := tc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tc *TestCreate) check() error {
	if _, ok := tc.mutation.TestID(); !ok {
		return &ValidationError{Name: "test_id", err: errors.New(`ent: missing required field "Test.test_id"`)}
	}
	if _, ok := tc.mutation.Comment(); !ok {
		return &ValidationError{Name: "comment", err: errors.New(`ent: missing required field "Test.comment"`)}
	}
	if _, ok := tc.mutation.ObjectID(); !ok {
		return &ValidationError{Name: "object_id", err: errors.New(`ent: missing required field "Test.object_id"`)}
	}
	if _, ok := tc.mutation.StateID(); !ok {
		return &ValidationError{Name: "state_id", err: errors.New(`ent: missing required field "Test.state_id"`)}
	}
	return nil
}

func (tc *TestCreate) sqlSave(ctx context.Context) (*Test, error) {
	if err := tc.check(); err != nil {
		return nil, err
	}
	_node, _spec := tc.createSpec()
	if err := sqlgraph.CreateNode(ctx, tc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	tc.mutation.id = &_node.ID
	tc.mutation.done = true
	return _node, nil
}

func (tc *TestCreate) createSpec() (*Test, *sqlgraph.CreateSpec) {
	var (
		_node = &Test{config: tc.config}
		_spec = sqlgraph.NewCreateSpec(test.Table, sqlgraph.NewFieldSpec(test.FieldID, field.TypeInt))
	)
	if value, ok := tc.mutation.TestID(); ok {
		_spec.SetField(test.FieldTestID, field.TypeString, value)
		_node.TestID = value
	}
	if value, ok := tc.mutation.Comment(); ok {
		_spec.SetField(test.FieldComment, field.TypeString, value)
		_node.Comment = value
	}
	if value, ok := tc.mutation.ObjectID(); ok {
		_spec.SetField(test.FieldObjectID, field.TypeString, value)
		_node.ObjectID = value
	}
	if value, ok := tc.mutation.StateID(); ok {
		_spec.SetField(test.FieldStateID, field.TypeString, value)
		_node.StateID = value
	}
	return _node, _spec
}

// TestCreateBulk is the builder for creating many Test entities in bulk.
type TestCreateBulk struct {
	config
	err      error
	builders []*TestCreate
}

// Save creates the Test entities in the database.
func (tcb *TestCreateBulk) Save(ctx context.Context) ([]*Test, error) {
	if tcb.err != nil {
		return nil, tcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(tcb.builders))
	nodes := make([]*Test, len(tcb.builders))
	mutators := make([]Mutator, len(tcb.builders))
	for i := range tcb.builders {
		func(i int, root context.Context) {
			builder := tcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*TestMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, tcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, tcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, tcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (tcb *TestCreateBulk) SaveX(ctx context.Context) []*Test {
	v, err := tcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tcb *TestCreateBulk) Exec(ctx context.Context) error {
	_, err := tcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tcb *TestCreateBulk) ExecX(ctx context.Context) {
	if err := tcb.Exec(ctx); err != nil {
		panic(err)
	}
}
