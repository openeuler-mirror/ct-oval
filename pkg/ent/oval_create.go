// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/oval"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// OvalCreate is the builder for creating a Oval entity.
type OvalCreate struct {
	config
	mutation *OvalMutation
	hooks    []Hook
}

// SetProductname sets the "productname" field.
func (oc *OvalCreate) SetProductname(s string) *OvalCreate {
	oc.mutation.SetProductname(s)
	return oc
}

// SetProductversion sets the "productversion" field.
func (oc *OvalCreate) SetProductversion(s string) *OvalCreate {
	oc.mutation.SetProductversion(s)
	return oc
}

// SetSchemaversion sets the "schemaversion" field.
func (oc *OvalCreate) SetSchemaversion(s string) *OvalCreate {
	oc.mutation.SetSchemaversion(s)
	return oc
}

// SetOvalversion sets the "ovalversion" field.
func (oc *OvalCreate) SetOvalversion(s string) *OvalCreate {
	oc.mutation.SetOvalversion(s)
	return oc
}

// SetClass sets the "class" field.
func (oc *OvalCreate) SetClass(s string) *OvalCreate {
	oc.mutation.SetClass(s)
	return oc
}

// SetFamily sets the "family" field.
func (oc *OvalCreate) SetFamily(s string) *OvalCreate {
	oc.mutation.SetFamily(s)
	return oc
}

// SetCopyright sets the "copyright" field.
func (oc *OvalCreate) SetCopyright(s string) *OvalCreate {
	oc.mutation.SetCopyright(s)
	return oc
}

// SetTimestamp sets the "timestamp" field.
func (oc *OvalCreate) SetTimestamp(s string) *OvalCreate {
	oc.mutation.SetTimestamp(s)
	return oc
}

// SetTitle sets the "title" field.
func (oc *OvalCreate) SetTitle(s string) *OvalCreate {
	oc.mutation.SetTitle(s)
	return oc
}

// SetDescription sets the "description" field.
func (oc *OvalCreate) SetDescription(s string) *OvalCreate {
	oc.mutation.SetDescription(s)
	return oc
}

// SetSeverity sets the "severity" field.
func (oc *OvalCreate) SetSeverity(s string) *OvalCreate {
	oc.mutation.SetSeverity(s)
	return oc
}

// SetIssuedate sets the "issuedate" field.
func (oc *OvalCreate) SetIssuedate(s string) *OvalCreate {
	oc.mutation.SetIssuedate(s)
	return oc
}

// SetPlatform sets the "platform" field.
func (oc *OvalCreate) SetPlatform(s string) *OvalCreate {
	oc.mutation.SetPlatform(s)
	return oc
}

// SetArchList sets the "arch_list" field.
func (oc *OvalCreate) SetArchList(s string) *OvalCreate {
	oc.mutation.SetArchList(s)
	return oc
}

// SetNillableArchList sets the "arch_list" field if the given value is not nil.
func (oc *OvalCreate) SetNillableArchList(s *string) *OvalCreate {
	if s != nil {
		oc.SetArchList(*s)
	}
	return oc
}

// SetCveList sets the "cve_list" field.
func (oc *OvalCreate) SetCveList(s string) *OvalCreate {
	oc.mutation.SetCveList(s)
	return oc
}

// SetNillableCveList sets the "cve_list" field if the given value is not nil.
func (oc *OvalCreate) SetNillableCveList(s *string) *OvalCreate {
	if s != nil {
		oc.SetCveList(*s)
	}
	return oc
}

// SetTestList sets the "test_list" field.
func (oc *OvalCreate) SetTestList(s string) *OvalCreate {
	oc.mutation.SetTestList(s)
	return oc
}

// SetNillableTestList sets the "test_list" field if the given value is not nil.
func (oc *OvalCreate) SetNillableTestList(s *string) *OvalCreate {
	if s != nil {
		oc.SetTestList(*s)
	}
	return oc
}

// SetObjectList sets the "object_list" field.
func (oc *OvalCreate) SetObjectList(s string) *OvalCreate {
	oc.mutation.SetObjectList(s)
	return oc
}

// SetNillableObjectList sets the "object_list" field if the given value is not nil.
func (oc *OvalCreate) SetNillableObjectList(s *string) *OvalCreate {
	if s != nil {
		oc.SetObjectList(*s)
	}
	return oc
}

// SetStateList sets the "state_list" field.
func (oc *OvalCreate) SetStateList(s string) *OvalCreate {
	oc.mutation.SetStateList(s)
	return oc
}

// SetNillableStateList sets the "state_list" field if the given value is not nil.
func (oc *OvalCreate) SetNillableStateList(s *string) *OvalCreate {
	if s != nil {
		oc.SetStateList(*s)
	}
	return oc
}

// SetID sets the "id" field.
func (oc *OvalCreate) SetID(s string) *OvalCreate {
	oc.mutation.SetID(s)
	return oc
}

// Mutation returns the OvalMutation object of the builder.
func (oc *OvalCreate) Mutation() *OvalMutation {
	return oc.mutation
}

// Save creates the Oval in the database.
func (oc *OvalCreate) Save(ctx context.Context) (*Oval, error) {
	oc.defaults()
	return withHooks(ctx, oc.sqlSave, oc.mutation, oc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (oc *OvalCreate) SaveX(ctx context.Context) *Oval {
	v, err := oc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (oc *OvalCreate) Exec(ctx context.Context) error {
	_, err := oc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (oc *OvalCreate) ExecX(ctx context.Context) {
	if err := oc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (oc *OvalCreate) defaults() {
	if _, ok := oc.mutation.ArchList(); !ok {
		v := oval.DefaultArchList
		oc.mutation.SetArchList(v)
	}
	if _, ok := oc.mutation.CveList(); !ok {
		v := oval.DefaultCveList
		oc.mutation.SetCveList(v)
	}
	if _, ok := oc.mutation.TestList(); !ok {
		v := oval.DefaultTestList
		oc.mutation.SetTestList(v)
	}
	if _, ok := oc.mutation.ObjectList(); !ok {
		v := oval.DefaultObjectList
		oc.mutation.SetObjectList(v)
	}
	if _, ok := oc.mutation.StateList(); !ok {
		v := oval.DefaultStateList
		oc.mutation.SetStateList(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (oc *OvalCreate) check() error {
	if _, ok := oc.mutation.Productname(); !ok {
		return &ValidationError{Name: "productname", err: errors.New(`ent: missing required field "Oval.productname"`)}
	}
	if _, ok := oc.mutation.Productversion(); !ok {
		return &ValidationError{Name: "productversion", err: errors.New(`ent: missing required field "Oval.productversion"`)}
	}
	if _, ok := oc.mutation.Schemaversion(); !ok {
		return &ValidationError{Name: "schemaversion", err: errors.New(`ent: missing required field "Oval.schemaversion"`)}
	}
	if _, ok := oc.mutation.Ovalversion(); !ok {
		return &ValidationError{Name: "ovalversion", err: errors.New(`ent: missing required field "Oval.ovalversion"`)}
	}
	if _, ok := oc.mutation.Class(); !ok {
		return &ValidationError{Name: "class", err: errors.New(`ent: missing required field "Oval.class"`)}
	}
	if _, ok := oc.mutation.Family(); !ok {
		return &ValidationError{Name: "family", err: errors.New(`ent: missing required field "Oval.family"`)}
	}
	if _, ok := oc.mutation.Copyright(); !ok {
		return &ValidationError{Name: "copyright", err: errors.New(`ent: missing required field "Oval.copyright"`)}
	}
	if _, ok := oc.mutation.Timestamp(); !ok {
		return &ValidationError{Name: "timestamp", err: errors.New(`ent: missing required field "Oval.timestamp"`)}
	}
	if _, ok := oc.mutation.Title(); !ok {
		return &ValidationError{Name: "title", err: errors.New(`ent: missing required field "Oval.title"`)}
	}
	if _, ok := oc.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Oval.description"`)}
	}
	if _, ok := oc.mutation.Severity(); !ok {
		return &ValidationError{Name: "severity", err: errors.New(`ent: missing required field "Oval.severity"`)}
	}
	if _, ok := oc.mutation.Issuedate(); !ok {
		return &ValidationError{Name: "issuedate", err: errors.New(`ent: missing required field "Oval.issuedate"`)}
	}
	if _, ok := oc.mutation.Platform(); !ok {
		return &ValidationError{Name: "platform", err: errors.New(`ent: missing required field "Oval.platform"`)}
	}
	if _, ok := oc.mutation.ArchList(); !ok {
		return &ValidationError{Name: "arch_list", err: errors.New(`ent: missing required field "Oval.arch_list"`)}
	}
	if _, ok := oc.mutation.CveList(); !ok {
		return &ValidationError{Name: "cve_list", err: errors.New(`ent: missing required field "Oval.cve_list"`)}
	}
	if _, ok := oc.mutation.TestList(); !ok {
		return &ValidationError{Name: "test_list", err: errors.New(`ent: missing required field "Oval.test_list"`)}
	}
	if _, ok := oc.mutation.ObjectList(); !ok {
		return &ValidationError{Name: "object_list", err: errors.New(`ent: missing required field "Oval.object_list"`)}
	}
	if _, ok := oc.mutation.StateList(); !ok {
		return &ValidationError{Name: "state_list", err: errors.New(`ent: missing required field "Oval.state_list"`)}
	}
	return nil
}

func (oc *OvalCreate) sqlSave(ctx context.Context) (*Oval, error) {
	if err := oc.check(); err != nil {
		return nil, err
	}
	_node, _spec := oc.createSpec()
	if err := sqlgraph.CreateNode(ctx, oc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected Oval.ID type: %T", _spec.ID.Value)
		}
	}
	oc.mutation.id = &_node.ID
	oc.mutation.done = true
	return _node, nil
}

func (oc *OvalCreate) createSpec() (*Oval, *sqlgraph.CreateSpec) {
	var (
		_node = &Oval{config: oc.config}
		_spec = sqlgraph.NewCreateSpec(oval.Table, sqlgraph.NewFieldSpec(oval.FieldID, field.TypeString))
	)
	if id, ok := oc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := oc.mutation.Productname(); ok {
		_spec.SetField(oval.FieldProductname, field.TypeString, value)
		_node.Productname = value
	}
	if value, ok := oc.mutation.Productversion(); ok {
		_spec.SetField(oval.FieldProductversion, field.TypeString, value)
		_node.Productversion = value
	}
	if value, ok := oc.mutation.Schemaversion(); ok {
		_spec.SetField(oval.FieldSchemaversion, field.TypeString, value)
		_node.Schemaversion = value
	}
	if value, ok := oc.mutation.Ovalversion(); ok {
		_spec.SetField(oval.FieldOvalversion, field.TypeString, value)
		_node.Ovalversion = value
	}
	if value, ok := oc.mutation.Class(); ok {
		_spec.SetField(oval.FieldClass, field.TypeString, value)
		_node.Class = value
	}
	if value, ok := oc.mutation.Family(); ok {
		_spec.SetField(oval.FieldFamily, field.TypeString, value)
		_node.Family = value
	}
	if value, ok := oc.mutation.Copyright(); ok {
		_spec.SetField(oval.FieldCopyright, field.TypeString, value)
		_node.Copyright = value
	}
	if value, ok := oc.mutation.Timestamp(); ok {
		_spec.SetField(oval.FieldTimestamp, field.TypeString, value)
		_node.Timestamp = value
	}
	if value, ok := oc.mutation.Title(); ok {
		_spec.SetField(oval.FieldTitle, field.TypeString, value)
		_node.Title = value
	}
	if value, ok := oc.mutation.Description(); ok {
		_spec.SetField(oval.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if value, ok := oc.mutation.Severity(); ok {
		_spec.SetField(oval.FieldSeverity, field.TypeString, value)
		_node.Severity = value
	}
	if value, ok := oc.mutation.Issuedate(); ok {
		_spec.SetField(oval.FieldIssuedate, field.TypeString, value)
		_node.Issuedate = value
	}
	if value, ok := oc.mutation.Platform(); ok {
		_spec.SetField(oval.FieldPlatform, field.TypeString, value)
		_node.Platform = value
	}
	if value, ok := oc.mutation.ArchList(); ok {
		_spec.SetField(oval.FieldArchList, field.TypeString, value)
		_node.ArchList = value
	}
	if value, ok := oc.mutation.CveList(); ok {
		_spec.SetField(oval.FieldCveList, field.TypeString, value)
		_node.CveList = value
	}
	if value, ok := oc.mutation.TestList(); ok {
		_spec.SetField(oval.FieldTestList, field.TypeString, value)
		_node.TestList = value
	}
	if value, ok := oc.mutation.ObjectList(); ok {
		_spec.SetField(oval.FieldObjectList, field.TypeString, value)
		_node.ObjectList = value
	}
	if value, ok := oc.mutation.StateList(); ok {
		_spec.SetField(oval.FieldStateList, field.TypeString, value)
		_node.StateList = value
	}
	return _node, _spec
}

// OvalCreateBulk is the builder for creating many Oval entities in bulk.
type OvalCreateBulk struct {
	config
	err      error
	builders []*OvalCreate
}

// Save creates the Oval entities in the database.
func (ocb *OvalCreateBulk) Save(ctx context.Context) ([]*Oval, error) {
	if ocb.err != nil {
		return nil, ocb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(ocb.builders))
	nodes := make([]*Oval, len(ocb.builders))
	mutators := make([]Mutator, len(ocb.builders))
	for i := range ocb.builders {
		func(i int, root context.Context) {
			builder := ocb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*OvalMutation)
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
					_, err = mutators[i+1].Mutate(root, ocb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ocb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
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
		if _, err := mutators[0].Mutate(ctx, ocb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ocb *OvalCreateBulk) SaveX(ctx context.Context) []*Oval {
	v, err := ocb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ocb *OvalCreateBulk) Exec(ctx context.Context) error {
	_, err := ocb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ocb *OvalCreateBulk) ExecX(ctx context.Context) {
	if err := ocb.Exec(ctx); err != nil {
		panic(err)
	}
}
