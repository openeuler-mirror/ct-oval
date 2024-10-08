package generator

import (
	"testing"
	"time"
)

// TestGenGenerator tests the GenGenerator function.
func TestGenGenerator(t *testing.T) {
	// Set up test data
	expectProductName := "CTyunOS Linux"
	expectProductVersion := "v1.0.0"
	expectSchemaVersion := "5.11"

	// Call the function
	generator := GenGenerator()

	// Check the returned generator struct
	if generator.ProductName != expectProductName {
		t.Errorf("Expected ProductName to be %s, but got %s", expectProductName, generator.ProductName)
	}
	if generator.ProductVersion != expectProductVersion {
		t.Errorf("Expected ProductVersion to be %s, but got %s", expectProductVersion, generator.ProductVersion)
	}
	if generator.SchemaVersion != expectSchemaVersion {
		t.Errorf("Expected SchemaVersion to be %s, but got %s", expectSchemaVersion, generator.SchemaVersion)
	}
	expectedTimestamp := time.Now().Format(time.RFC3339)
	if generator.Timestamp != expectedTimestamp {
		t.Errorf("Expected Timestamp to be %s, but got %s", expectedTimestamp, generator.Timestamp)
	}
}
