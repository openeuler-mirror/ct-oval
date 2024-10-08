// Code generated by ent, DO NOT EDIT.

package ent

import (
	"ct_oval_tool/pkg/ent/test"
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// Test is the model entity for the Test schema.
type Test struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// TestID holds the value of the "test_id" field.
	TestID string `json:"test_id,omitempty"`
	// Comment holds the value of the "comment" field.
	Comment string `json:"comment,omitempty"`
	// ObjectID holds the value of the "object_id" field.
	ObjectID string `json:"object_id,omitempty"`
	// StateID holds the value of the "state_id" field.
	StateID      string `json:"state_id,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Test) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case test.FieldID:
			values[i] = new(sql.NullInt64)
		case test.FieldTestID, test.FieldComment, test.FieldObjectID, test.FieldStateID:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Test fields.
func (t *Test) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case test.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			t.ID = int(value.Int64)
		case test.FieldTestID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field test_id", values[i])
			} else if value.Valid {
				t.TestID = value.String
			}
		case test.FieldComment:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field comment", values[i])
			} else if value.Valid {
				t.Comment = value.String
			}
		case test.FieldObjectID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field object_id", values[i])
			} else if value.Valid {
				t.ObjectID = value.String
			}
		case test.FieldStateID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field state_id", values[i])
			} else if value.Valid {
				t.StateID = value.String
			}
		default:
			t.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Test.
// This includes values selected through modifiers, order, etc.
func (t *Test) Value(name string) (ent.Value, error) {
	return t.selectValues.Get(name)
}

// Update returns a builder for updating this Test.
// Note that you need to call Test.Unwrap() before calling this method if this Test
// was returned from a transaction, and the transaction was committed or rolled back.
func (t *Test) Update() *TestUpdateOne {
	return NewTestClient(t.config).UpdateOne(t)
}

// Unwrap unwraps the Test entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (t *Test) Unwrap() *Test {
	_tx, ok := t.config.driver.(*txDriver)
	if !ok {
		panic("ent: Test is not a transactional entity")
	}
	t.config.driver = _tx.drv
	return t
}

// String implements the fmt.Stringer.
func (t *Test) String() string {
	var builder strings.Builder
	builder.WriteString("Test(")
	builder.WriteString(fmt.Sprintf("id=%v, ", t.ID))
	builder.WriteString("test_id=")
	builder.WriteString(t.TestID)
	builder.WriteString(", ")
	builder.WriteString("comment=")
	builder.WriteString(t.Comment)
	builder.WriteString(", ")
	builder.WriteString("object_id=")
	builder.WriteString(t.ObjectID)
	builder.WriteString(", ")
	builder.WriteString("state_id=")
	builder.WriteString(t.StateID)
	builder.WriteByte(')')
	return builder.String()
}

// Tests is a parsable slice of Test.
type Tests []*Test