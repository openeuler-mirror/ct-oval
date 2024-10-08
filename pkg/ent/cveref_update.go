// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/cveref"
	"ct_oval_tool/pkg/ent/predicate"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// CverefUpdate is the builder for updating Cveref entities.
type CverefUpdate struct {
	config
	hooks    []Hook
	mutation *CverefMutation
}

// Where appends a list predicates to the CverefUpdate builder.
func (cu *CverefUpdate) Where(ps ...predicate.Cveref) *CverefUpdate {
	cu.mutation.Where(ps...)
	return cu
}

// SetRefID sets the "ref_id" field.
func (cu *CverefUpdate) SetRefID(s string) *CverefUpdate {
	cu.mutation.SetRefID(s)
	return cu
}

// SetNillableRefID sets the "ref_id" field if the given value is not nil.
func (cu *CverefUpdate) SetNillableRefID(s *string) *CverefUpdate {
	if s != nil {
		cu.SetRefID(*s)
	}
	return cu
}

// SetRefURL sets the "ref_url" field.
func (cu *CverefUpdate) SetRefURL(s string) *CverefUpdate {
	cu.mutation.SetRefURL(s)
	return cu
}

// SetNillableRefURL sets the "ref_url" field if the given value is not nil.
func (cu *CverefUpdate) SetNillableRefURL(s *string) *CverefUpdate {
	if s != nil {
		cu.SetRefURL(*s)
	}
	return cu
}

// Mutation returns the CverefMutation object of the builder.
func (cu *CverefUpdate) Mutation() *CverefMutation {
	return cu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (cu *CverefUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, cu.sqlSave, cu.mutation, cu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cu *CverefUpdate) SaveX(ctx context.Context) int {
	affected, err := cu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (cu *CverefUpdate) Exec(ctx context.Context) error {
	_, err := cu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cu *CverefUpdate) ExecX(ctx context.Context) {
	if err := cu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (cu *CverefUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(cveref.Table, cveref.Columns, sqlgraph.NewFieldSpec(cveref.FieldID, field.TypeInt))
	if ps := cu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cu.mutation.RefID(); ok {
		_spec.SetField(cveref.FieldRefID, field.TypeString, value)
	}
	if value, ok := cu.mutation.RefURL(); ok {
		_spec.SetField(cveref.FieldRefURL, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, cu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{cveref.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	cu.mutation.done = true
	return n, nil
}

// CverefUpdateOne is the builder for updating a single Cveref entity.
type CverefUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *CverefMutation
}

// SetRefID sets the "ref_id" field.
func (cuo *CverefUpdateOne) SetRefID(s string) *CverefUpdateOne {
	cuo.mutation.SetRefID(s)
	return cuo
}

// SetNillableRefID sets the "ref_id" field if the given value is not nil.
func (cuo *CverefUpdateOne) SetNillableRefID(s *string) *CverefUpdateOne {
	if s != nil {
		cuo.SetRefID(*s)
	}
	return cuo
}

// SetRefURL sets the "ref_url" field.
func (cuo *CverefUpdateOne) SetRefURL(s string) *CverefUpdateOne {
	cuo.mutation.SetRefURL(s)
	return cuo
}

// SetNillableRefURL sets the "ref_url" field if the given value is not nil.
func (cuo *CverefUpdateOne) SetNillableRefURL(s *string) *CverefUpdateOne {
	if s != nil {
		cuo.SetRefURL(*s)
	}
	return cuo
}

// Mutation returns the CverefMutation object of the builder.
func (cuo *CverefUpdateOne) Mutation() *CverefMutation {
	return cuo.mutation
}

// Where appends a list predicates to the CverefUpdate builder.
func (cuo *CverefUpdateOne) Where(ps ...predicate.Cveref) *CverefUpdateOne {
	cuo.mutation.Where(ps...)
	return cuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (cuo *CverefUpdateOne) Select(field string, fields ...string) *CverefUpdateOne {
	cuo.fields = append([]string{field}, fields...)
	return cuo
}

// Save executes the query and returns the updated Cveref entity.
func (cuo *CverefUpdateOne) Save(ctx context.Context) (*Cveref, error) {
	return withHooks(ctx, cuo.sqlSave, cuo.mutation, cuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cuo *CverefUpdateOne) SaveX(ctx context.Context) *Cveref {
	node, err := cuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (cuo *CverefUpdateOne) Exec(ctx context.Context) error {
	_, err := cuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cuo *CverefUpdateOne) ExecX(ctx context.Context) {
	if err := cuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (cuo *CverefUpdateOne) sqlSave(ctx context.Context) (_node *Cveref, err error) {
	_spec := sqlgraph.NewUpdateSpec(cveref.Table, cveref.Columns, sqlgraph.NewFieldSpec(cveref.FieldID, field.TypeInt))
	id, ok := cuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Cveref.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := cuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, cveref.FieldID)
		for _, f := range fields {
			if !cveref.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != cveref.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := cuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cuo.mutation.RefID(); ok {
		_spec.SetField(cveref.FieldRefID, field.TypeString, value)
	}
	if value, ok := cuo.mutation.RefURL(); ok {
		_spec.SetField(cveref.FieldRefURL, field.TypeString, value)
	}
	_node = &Cveref{config: cuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, cuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{cveref.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	cuo.mutation.done = true
	return _node, nil
}
