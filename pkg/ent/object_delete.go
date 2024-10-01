// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/object"
	"ct_oval_tool/pkg/ent/predicate"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// ObjectDelete is the builder for deleting a Object entity.
type ObjectDelete struct {
	config
	hooks    []Hook
	mutation *ObjectMutation
}

// Where appends a list predicates to the ObjectDelete builder.
func (od *ObjectDelete) Where(ps ...predicate.Object) *ObjectDelete {
	od.mutation.Where(ps...)
	return od
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (od *ObjectDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, od.sqlExec, od.mutation, od.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (od *ObjectDelete) ExecX(ctx context.Context) int {
	n, err := od.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (od *ObjectDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(object.Table, sqlgraph.NewFieldSpec(object.FieldID, field.TypeInt))
	if ps := od.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, od.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	od.mutation.done = true
	return affected, err
}

// ObjectDeleteOne is the builder for deleting a single Object entity.
type ObjectDeleteOne struct {
	od *ObjectDelete
}

// Where appends a list predicates to the ObjectDelete builder.
func (odo *ObjectDeleteOne) Where(ps ...predicate.Object) *ObjectDeleteOne {
	odo.od.mutation.Where(ps...)
	return odo
}

// Exec executes the deletion query.
func (odo *ObjectDeleteOne) Exec(ctx context.Context) error {
	n, err := odo.od.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{object.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (odo *ObjectDeleteOne) ExecX(ctx context.Context) {
	if err := odo.Exec(ctx); err != nil {
		panic(err)
	}
}
