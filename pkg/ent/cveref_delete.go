// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/cveref"
	"ct_oval_tool/pkg/ent/predicate"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// CverefDelete is the builder for deleting a Cveref entity.
type CverefDelete struct {
	config
	hooks    []Hook
	mutation *CverefMutation
}

// Where appends a list predicates to the CverefDelete builder.
func (cd *CverefDelete) Where(ps ...predicate.Cveref) *CverefDelete {
	cd.mutation.Where(ps...)
	return cd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (cd *CverefDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, cd.sqlExec, cd.mutation, cd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (cd *CverefDelete) ExecX(ctx context.Context) int {
	n, err := cd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (cd *CverefDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(cveref.Table, sqlgraph.NewFieldSpec(cveref.FieldID, field.TypeInt))
	if ps := cd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, cd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	cd.mutation.done = true
	return affected, err
}

// CverefDeleteOne is the builder for deleting a single Cveref entity.
type CverefDeleteOne struct {
	cd *CverefDelete
}

// Where appends a list predicates to the CverefDelete builder.
func (cdo *CverefDeleteOne) Where(ps ...predicate.Cveref) *CverefDeleteOne {
	cdo.cd.mutation.Where(ps...)
	return cdo
}

// Exec executes the deletion query.
func (cdo *CverefDeleteOne) Exec(ctx context.Context) error {
	n, err := cdo.cd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{cveref.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (cdo *CverefDeleteOne) ExecX(ctx context.Context) {
	if err := cdo.Exec(ctx); err != nil {
		panic(err)
	}
}