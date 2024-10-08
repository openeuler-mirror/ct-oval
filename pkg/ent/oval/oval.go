// Code generated by ent, DO NOT EDIT.

package oval

import (
	"entgo.io/ent/dialect/sql"
)

const (
	// Label holds the string label denoting the oval type in the database.
	Label = "oval"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldProductname holds the string denoting the productname field in the database.
	FieldProductname = "productname"
	// FieldProductversion holds the string denoting the productversion field in the database.
	FieldProductversion = "productversion"
	// FieldSchemaversion holds the string denoting the schemaversion field in the database.
	FieldSchemaversion = "schemaversion"
	// FieldOvalversion holds the string denoting the ovalversion field in the database.
	FieldOvalversion = "ovalversion"
	// FieldClass holds the string denoting the class field in the database.
	FieldClass = "class"
	// FieldFamily holds the string denoting the family field in the database.
	FieldFamily = "family"
	// FieldCopyright holds the string denoting the copyright field in the database.
	FieldCopyright = "copyright"
	// FieldTimestamp holds the string denoting the timestamp field in the database.
	FieldTimestamp = "timestamp"
	// FieldTitle holds the string denoting the title field in the database.
	FieldTitle = "title"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldSeverity holds the string denoting the severity field in the database.
	FieldSeverity = "severity"
	// FieldIssuedate holds the string denoting the issuedate field in the database.
	FieldIssuedate = "issuedate"
	// FieldPlatform holds the string denoting the platform field in the database.
	FieldPlatform = "platform"
	// FieldArchList holds the string denoting the arch_list field in the database.
	FieldArchList = "arch_list"
	// FieldCveList holds the string denoting the cve_list field in the database.
	FieldCveList = "cve_list"
	// FieldTestList holds the string denoting the test_list field in the database.
	FieldTestList = "test_list"
	// FieldObjectList holds the string denoting the object_list field in the database.
	FieldObjectList = "object_list"
	// FieldStateList holds the string denoting the state_list field in the database.
	FieldStateList = "state_list"
	// Table holds the table name of the oval in the database.
	Table = "ovals"
)

// Columns holds all SQL columns for oval fields.
var Columns = []string{
	FieldID,
	FieldProductname,
	FieldProductversion,
	FieldSchemaversion,
	FieldOvalversion,
	FieldClass,
	FieldFamily,
	FieldCopyright,
	FieldTimestamp,
	FieldTitle,
	FieldDescription,
	FieldSeverity,
	FieldIssuedate,
	FieldPlatform,
	FieldArchList,
	FieldCveList,
	FieldTestList,
	FieldObjectList,
	FieldStateList,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultArchList holds the default value on creation for the "arch_list" field.
	DefaultArchList string
	// DefaultCveList holds the default value on creation for the "cve_list" field.
	DefaultCveList string
	// DefaultTestList holds the default value on creation for the "test_list" field.
	DefaultTestList string
	// DefaultObjectList holds the default value on creation for the "object_list" field.
	DefaultObjectList string
	// DefaultStateList holds the default value on creation for the "state_list" field.
	DefaultStateList string
)

// OrderOption defines the ordering options for the Oval queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByProductname orders the results by the productname field.
func ByProductname(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldProductname, opts...).ToFunc()
}

// ByProductversion orders the results by the productversion field.
func ByProductversion(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldProductversion, opts...).ToFunc()
}

// BySchemaversion orders the results by the schemaversion field.
func BySchemaversion(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSchemaversion, opts...).ToFunc()
}

// ByOvalversion orders the results by the ovalversion field.
func ByOvalversion(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldOvalversion, opts...).ToFunc()
}

// ByClass orders the results by the class field.
func ByClass(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClass, opts...).ToFunc()
}

// ByFamily orders the results by the family field.
func ByFamily(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldFamily, opts...).ToFunc()
}

// ByCopyright orders the results by the copyright field.
func ByCopyright(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCopyright, opts...).ToFunc()
}

// ByTimestamp orders the results by the timestamp field.
func ByTimestamp(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldTimestamp, opts...).ToFunc()
}

// ByTitle orders the results by the title field.
func ByTitle(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldTitle, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// BySeverity orders the results by the severity field.
func BySeverity(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSeverity, opts...).ToFunc()
}

// ByIssuedate orders the results by the issuedate field.
func ByIssuedate(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIssuedate, opts...).ToFunc()
}

// ByPlatform orders the results by the platform field.
func ByPlatform(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPlatform, opts...).ToFunc()
}

// ByArchList orders the results by the arch_list field.
func ByArchList(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldArchList, opts...).ToFunc()
}

// ByCveList orders the results by the cve_list field.
func ByCveList(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCveList, opts...).ToFunc()
}

// ByTestList orders the results by the test_list field.
func ByTestList(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldTestList, opts...).ToFunc()
}

// ByObjectList orders the results by the object_list field.
func ByObjectList(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldObjectList, opts...).ToFunc()
}

// ByStateList orders the results by the state_list field.
func ByStateList(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldStateList, opts...).ToFunc()
}
