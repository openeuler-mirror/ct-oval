// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"ct_oval_tool/pkg/ent/oval"
	"ct_oval_tool/pkg/ent/predicate"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// OvalUpdate is the builder for updating Oval entities.
type OvalUpdate struct {
	config
	hooks    []Hook
	mutation *OvalMutation
}

// Where appends a list predicates to the OvalUpdate builder.
func (ou *OvalUpdate) Where(ps ...predicate.Oval) *OvalUpdate {
	ou.mutation.Where(ps...)
	return ou
}

// SetProductname sets the "productname" field.
func (ou *OvalUpdate) SetProductname(s string) *OvalUpdate {
	ou.mutation.SetProductname(s)
	return ou
}

// SetNillableProductname sets the "productname" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableProductname(s *string) *OvalUpdate {
	if s != nil {
		ou.SetProductname(*s)
	}
	return ou
}

// SetProductversion sets the "productversion" field.
func (ou *OvalUpdate) SetProductversion(s string) *OvalUpdate {
	ou.mutation.SetProductversion(s)
	return ou
}

// SetNillableProductversion sets the "productversion" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableProductversion(s *string) *OvalUpdate {
	if s != nil {
		ou.SetProductversion(*s)
	}
	return ou
}

// SetSchemaversion sets the "schemaversion" field.
func (ou *OvalUpdate) SetSchemaversion(s string) *OvalUpdate {
	ou.mutation.SetSchemaversion(s)
	return ou
}

// SetNillableSchemaversion sets the "schemaversion" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableSchemaversion(s *string) *OvalUpdate {
	if s != nil {
		ou.SetSchemaversion(*s)
	}
	return ou
}

// SetOvalversion sets the "ovalversion" field.
func (ou *OvalUpdate) SetOvalversion(s string) *OvalUpdate {
	ou.mutation.SetOvalversion(s)
	return ou
}

// SetNillableOvalversion sets the "ovalversion" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableOvalversion(s *string) *OvalUpdate {
	if s != nil {
		ou.SetOvalversion(*s)
	}
	return ou
}

// SetClass sets the "class" field.
func (ou *OvalUpdate) SetClass(s string) *OvalUpdate {
	ou.mutation.SetClass(s)
	return ou
}

// SetNillableClass sets the "class" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableClass(s *string) *OvalUpdate {
	if s != nil {
		ou.SetClass(*s)
	}
	return ou
}

// SetFamily sets the "family" field.
func (ou *OvalUpdate) SetFamily(s string) *OvalUpdate {
	ou.mutation.SetFamily(s)
	return ou
}

// SetNillableFamily sets the "family" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableFamily(s *string) *OvalUpdate {
	if s != nil {
		ou.SetFamily(*s)
	}
	return ou
}

// SetCopyright sets the "copyright" field.
func (ou *OvalUpdate) SetCopyright(s string) *OvalUpdate {
	ou.mutation.SetCopyright(s)
	return ou
}

// SetNillableCopyright sets the "copyright" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableCopyright(s *string) *OvalUpdate {
	if s != nil {
		ou.SetCopyright(*s)
	}
	return ou
}

// SetTimestamp sets the "timestamp" field.
func (ou *OvalUpdate) SetTimestamp(s string) *OvalUpdate {
	ou.mutation.SetTimestamp(s)
	return ou
}

// SetNillableTimestamp sets the "timestamp" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableTimestamp(s *string) *OvalUpdate {
	if s != nil {
		ou.SetTimestamp(*s)
	}
	return ou
}

// SetTitle sets the "title" field.
func (ou *OvalUpdate) SetTitle(s string) *OvalUpdate {
	ou.mutation.SetTitle(s)
	return ou
}

// SetNillableTitle sets the "title" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableTitle(s *string) *OvalUpdate {
	if s != nil {
		ou.SetTitle(*s)
	}
	return ou
}

// SetDescription sets the "description" field.
func (ou *OvalUpdate) SetDescription(s string) *OvalUpdate {
	ou.mutation.SetDescription(s)
	return ou
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableDescription(s *string) *OvalUpdate {
	if s != nil {
		ou.SetDescription(*s)
	}
	return ou
}

// SetSeverity sets the "severity" field.
func (ou *OvalUpdate) SetSeverity(s string) *OvalUpdate {
	ou.mutation.SetSeverity(s)
	return ou
}

// SetNillableSeverity sets the "severity" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableSeverity(s *string) *OvalUpdate {
	if s != nil {
		ou.SetSeverity(*s)
	}
	return ou
}

// SetIssuedate sets the "issuedate" field.
func (ou *OvalUpdate) SetIssuedate(s string) *OvalUpdate {
	ou.mutation.SetIssuedate(s)
	return ou
}

// SetNillableIssuedate sets the "issuedate" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableIssuedate(s *string) *OvalUpdate {
	if s != nil {
		ou.SetIssuedate(*s)
	}
	return ou
}

// SetPlatform sets the "platform" field.
func (ou *OvalUpdate) SetPlatform(s string) *OvalUpdate {
	ou.mutation.SetPlatform(s)
	return ou
}

// SetNillablePlatform sets the "platform" field if the given value is not nil.
func (ou *OvalUpdate) SetNillablePlatform(s *string) *OvalUpdate {
	if s != nil {
		ou.SetPlatform(*s)
	}
	return ou
}

// SetArchList sets the "arch_list" field.
func (ou *OvalUpdate) SetArchList(s string) *OvalUpdate {
	ou.mutation.SetArchList(s)
	return ou
}

// SetNillableArchList sets the "arch_list" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableArchList(s *string) *OvalUpdate {
	if s != nil {
		ou.SetArchList(*s)
	}
	return ou
}

// SetCveList sets the "cve_list" field.
func (ou *OvalUpdate) SetCveList(s string) *OvalUpdate {
	ou.mutation.SetCveList(s)
	return ou
}

// SetNillableCveList sets the "cve_list" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableCveList(s *string) *OvalUpdate {
	if s != nil {
		ou.SetCveList(*s)
	}
	return ou
}

// SetTestList sets the "test_list" field.
func (ou *OvalUpdate) SetTestList(s string) *OvalUpdate {
	ou.mutation.SetTestList(s)
	return ou
}

// SetNillableTestList sets the "test_list" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableTestList(s *string) *OvalUpdate {
	if s != nil {
		ou.SetTestList(*s)
	}
	return ou
}

// SetObjectList sets the "object_list" field.
func (ou *OvalUpdate) SetObjectList(s string) *OvalUpdate {
	ou.mutation.SetObjectList(s)
	return ou
}

// SetNillableObjectList sets the "object_list" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableObjectList(s *string) *OvalUpdate {
	if s != nil {
		ou.SetObjectList(*s)
	}
	return ou
}

// SetStateList sets the "state_list" field.
func (ou *OvalUpdate) SetStateList(s string) *OvalUpdate {
	ou.mutation.SetStateList(s)
	return ou
}

// SetNillableStateList sets the "state_list" field if the given value is not nil.
func (ou *OvalUpdate) SetNillableStateList(s *string) *OvalUpdate {
	if s != nil {
		ou.SetStateList(*s)
	}
	return ou
}

// Mutation returns the OvalMutation object of the builder.
func (ou *OvalUpdate) Mutation() *OvalMutation {
	return ou.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (ou *OvalUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, ou.sqlSave, ou.mutation, ou.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ou *OvalUpdate) SaveX(ctx context.Context) int {
	affected, err := ou.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (ou *OvalUpdate) Exec(ctx context.Context) error {
	_, err := ou.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ou *OvalUpdate) ExecX(ctx context.Context) {
	if err := ou.Exec(ctx); err != nil {
		panic(err)
	}
}

func (ou *OvalUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(oval.Table, oval.Columns, sqlgraph.NewFieldSpec(oval.FieldID, field.TypeString))
	if ps := ou.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ou.mutation.Productname(); ok {
		_spec.SetField(oval.FieldProductname, field.TypeString, value)
	}
	if value, ok := ou.mutation.Productversion(); ok {
		_spec.SetField(oval.FieldProductversion, field.TypeString, value)
	}
	if value, ok := ou.mutation.Schemaversion(); ok {
		_spec.SetField(oval.FieldSchemaversion, field.TypeString, value)
	}
	if value, ok := ou.mutation.Ovalversion(); ok {
		_spec.SetField(oval.FieldOvalversion, field.TypeString, value)
	}
	if value, ok := ou.mutation.Class(); ok {
		_spec.SetField(oval.FieldClass, field.TypeString, value)
	}
	if value, ok := ou.mutation.Family(); ok {
		_spec.SetField(oval.FieldFamily, field.TypeString, value)
	}
	if value, ok := ou.mutation.Copyright(); ok {
		_spec.SetField(oval.FieldCopyright, field.TypeString, value)
	}
	if value, ok := ou.mutation.Timestamp(); ok {
		_spec.SetField(oval.FieldTimestamp, field.TypeString, value)
	}
	if value, ok := ou.mutation.Title(); ok {
		_spec.SetField(oval.FieldTitle, field.TypeString, value)
	}
	if value, ok := ou.mutation.Description(); ok {
		_spec.SetField(oval.FieldDescription, field.TypeString, value)
	}
	if value, ok := ou.mutation.Severity(); ok {
		_spec.SetField(oval.FieldSeverity, field.TypeString, value)
	}
	if value, ok := ou.mutation.Issuedate(); ok {
		_spec.SetField(oval.FieldIssuedate, field.TypeString, value)
	}
	if value, ok := ou.mutation.Platform(); ok {
		_spec.SetField(oval.FieldPlatform, field.TypeString, value)
	}
	if value, ok := ou.mutation.ArchList(); ok {
		_spec.SetField(oval.FieldArchList, field.TypeString, value)
	}
	if value, ok := ou.mutation.CveList(); ok {
		_spec.SetField(oval.FieldCveList, field.TypeString, value)
	}
	if value, ok := ou.mutation.TestList(); ok {
		_spec.SetField(oval.FieldTestList, field.TypeString, value)
	}
	if value, ok := ou.mutation.ObjectList(); ok {
		_spec.SetField(oval.FieldObjectList, field.TypeString, value)
	}
	if value, ok := ou.mutation.StateList(); ok {
		_spec.SetField(oval.FieldStateList, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, ou.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oval.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	ou.mutation.done = true
	return n, nil
}

// OvalUpdateOne is the builder for updating a single Oval entity.
type OvalUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *OvalMutation
}

// SetProductname sets the "productname" field.
func (ouo *OvalUpdateOne) SetProductname(s string) *OvalUpdateOne {
	ouo.mutation.SetProductname(s)
	return ouo
}

// SetNillableProductname sets the "productname" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableProductname(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetProductname(*s)
	}
	return ouo
}

// SetProductversion sets the "productversion" field.
func (ouo *OvalUpdateOne) SetProductversion(s string) *OvalUpdateOne {
	ouo.mutation.SetProductversion(s)
	return ouo
}

// SetNillableProductversion sets the "productversion" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableProductversion(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetProductversion(*s)
	}
	return ouo
}

// SetSchemaversion sets the "schemaversion" field.
func (ouo *OvalUpdateOne) SetSchemaversion(s string) *OvalUpdateOne {
	ouo.mutation.SetSchemaversion(s)
	return ouo
}

// SetNillableSchemaversion sets the "schemaversion" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableSchemaversion(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetSchemaversion(*s)
	}
	return ouo
}

// SetOvalversion sets the "ovalversion" field.
func (ouo *OvalUpdateOne) SetOvalversion(s string) *OvalUpdateOne {
	ouo.mutation.SetOvalversion(s)
	return ouo
}

// SetNillableOvalversion sets the "ovalversion" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableOvalversion(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetOvalversion(*s)
	}
	return ouo
}

// SetClass sets the "class" field.
func (ouo *OvalUpdateOne) SetClass(s string) *OvalUpdateOne {
	ouo.mutation.SetClass(s)
	return ouo
}

// SetNillableClass sets the "class" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableClass(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetClass(*s)
	}
	return ouo
}

// SetFamily sets the "family" field.
func (ouo *OvalUpdateOne) SetFamily(s string) *OvalUpdateOne {
	ouo.mutation.SetFamily(s)
	return ouo
}

// SetNillableFamily sets the "family" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableFamily(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetFamily(*s)
	}
	return ouo
}

// SetCopyright sets the "copyright" field.
func (ouo *OvalUpdateOne) SetCopyright(s string) *OvalUpdateOne {
	ouo.mutation.SetCopyright(s)
	return ouo
}

// SetNillableCopyright sets the "copyright" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableCopyright(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetCopyright(*s)
	}
	return ouo
}

// SetTimestamp sets the "timestamp" field.
func (ouo *OvalUpdateOne) SetTimestamp(s string) *OvalUpdateOne {
	ouo.mutation.SetTimestamp(s)
	return ouo
}

// SetNillableTimestamp sets the "timestamp" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableTimestamp(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetTimestamp(*s)
	}
	return ouo
}

// SetTitle sets the "title" field.
func (ouo *OvalUpdateOne) SetTitle(s string) *OvalUpdateOne {
	ouo.mutation.SetTitle(s)
	return ouo
}

// SetNillableTitle sets the "title" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableTitle(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetTitle(*s)
	}
	return ouo
}

// SetDescription sets the "description" field.
func (ouo *OvalUpdateOne) SetDescription(s string) *OvalUpdateOne {
	ouo.mutation.SetDescription(s)
	return ouo
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableDescription(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetDescription(*s)
	}
	return ouo
}

// SetSeverity sets the "severity" field.
func (ouo *OvalUpdateOne) SetSeverity(s string) *OvalUpdateOne {
	ouo.mutation.SetSeverity(s)
	return ouo
}

// SetNillableSeverity sets the "severity" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableSeverity(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetSeverity(*s)
	}
	return ouo
}

// SetIssuedate sets the "issuedate" field.
func (ouo *OvalUpdateOne) SetIssuedate(s string) *OvalUpdateOne {
	ouo.mutation.SetIssuedate(s)
	return ouo
}

// SetNillableIssuedate sets the "issuedate" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableIssuedate(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetIssuedate(*s)
	}
	return ouo
}

// SetPlatform sets the "platform" field.
func (ouo *OvalUpdateOne) SetPlatform(s string) *OvalUpdateOne {
	ouo.mutation.SetPlatform(s)
	return ouo
}

// SetNillablePlatform sets the "platform" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillablePlatform(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetPlatform(*s)
	}
	return ouo
}

// SetArchList sets the "arch_list" field.
func (ouo *OvalUpdateOne) SetArchList(s string) *OvalUpdateOne {
	ouo.mutation.SetArchList(s)
	return ouo
}

// SetNillableArchList sets the "arch_list" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableArchList(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetArchList(*s)
	}
	return ouo
}

// SetCveList sets the "cve_list" field.
func (ouo *OvalUpdateOne) SetCveList(s string) *OvalUpdateOne {
	ouo.mutation.SetCveList(s)
	return ouo
}

// SetNillableCveList sets the "cve_list" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableCveList(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetCveList(*s)
	}
	return ouo
}

// SetTestList sets the "test_list" field.
func (ouo *OvalUpdateOne) SetTestList(s string) *OvalUpdateOne {
	ouo.mutation.SetTestList(s)
	return ouo
}

// SetNillableTestList sets the "test_list" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableTestList(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetTestList(*s)
	}
	return ouo
}

// SetObjectList sets the "object_list" field.
func (ouo *OvalUpdateOne) SetObjectList(s string) *OvalUpdateOne {
	ouo.mutation.SetObjectList(s)
	return ouo
}

// SetNillableObjectList sets the "object_list" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableObjectList(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetObjectList(*s)
	}
	return ouo
}

// SetStateList sets the "state_list" field.
func (ouo *OvalUpdateOne) SetStateList(s string) *OvalUpdateOne {
	ouo.mutation.SetStateList(s)
	return ouo
}

// SetNillableStateList sets the "state_list" field if the given value is not nil.
func (ouo *OvalUpdateOne) SetNillableStateList(s *string) *OvalUpdateOne {
	if s != nil {
		ouo.SetStateList(*s)
	}
	return ouo
}

// Mutation returns the OvalMutation object of the builder.
func (ouo *OvalUpdateOne) Mutation() *OvalMutation {
	return ouo.mutation
}

// Where appends a list predicates to the OvalUpdate builder.
func (ouo *OvalUpdateOne) Where(ps ...predicate.Oval) *OvalUpdateOne {
	ouo.mutation.Where(ps...)
	return ouo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ouo *OvalUpdateOne) Select(field string, fields ...string) *OvalUpdateOne {
	ouo.fields = append([]string{field}, fields...)
	return ouo
}

// Save executes the query and returns the updated Oval entity.
func (ouo *OvalUpdateOne) Save(ctx context.Context) (*Oval, error) {
	return withHooks(ctx, ouo.sqlSave, ouo.mutation, ouo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ouo *OvalUpdateOne) SaveX(ctx context.Context) *Oval {
	node, err := ouo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ouo *OvalUpdateOne) Exec(ctx context.Context) error {
	_, err := ouo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ouo *OvalUpdateOne) ExecX(ctx context.Context) {
	if err := ouo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (ouo *OvalUpdateOne) sqlSave(ctx context.Context) (_node *Oval, err error) {
	_spec := sqlgraph.NewUpdateSpec(oval.Table, oval.Columns, sqlgraph.NewFieldSpec(oval.FieldID, field.TypeString))
	id, ok := ouo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Oval.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ouo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oval.FieldID)
		for _, f := range fields {
			if !oval.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != oval.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ouo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ouo.mutation.Productname(); ok {
		_spec.SetField(oval.FieldProductname, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Productversion(); ok {
		_spec.SetField(oval.FieldProductversion, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Schemaversion(); ok {
		_spec.SetField(oval.FieldSchemaversion, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Ovalversion(); ok {
		_spec.SetField(oval.FieldOvalversion, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Class(); ok {
		_spec.SetField(oval.FieldClass, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Family(); ok {
		_spec.SetField(oval.FieldFamily, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Copyright(); ok {
		_spec.SetField(oval.FieldCopyright, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Timestamp(); ok {
		_spec.SetField(oval.FieldTimestamp, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Title(); ok {
		_spec.SetField(oval.FieldTitle, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Description(); ok {
		_spec.SetField(oval.FieldDescription, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Severity(); ok {
		_spec.SetField(oval.FieldSeverity, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Issuedate(); ok {
		_spec.SetField(oval.FieldIssuedate, field.TypeString, value)
	}
	if value, ok := ouo.mutation.Platform(); ok {
		_spec.SetField(oval.FieldPlatform, field.TypeString, value)
	}
	if value, ok := ouo.mutation.ArchList(); ok {
		_spec.SetField(oval.FieldArchList, field.TypeString, value)
	}
	if value, ok := ouo.mutation.CveList(); ok {
		_spec.SetField(oval.FieldCveList, field.TypeString, value)
	}
	if value, ok := ouo.mutation.TestList(); ok {
		_spec.SetField(oval.FieldTestList, field.TypeString, value)
	}
	if value, ok := ouo.mutation.ObjectList(); ok {
		_spec.SetField(oval.FieldObjectList, field.TypeString, value)
	}
	if value, ok := ouo.mutation.StateList(); ok {
		_spec.SetField(oval.FieldStateList, field.TypeString, value)
	}
	_node = &Oval{config: ouo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ouo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oval.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	ouo.mutation.done = true
	return _node, nil
}