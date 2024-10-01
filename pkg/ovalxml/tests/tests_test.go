package tests

import (
	"ct_oval_tool/pkg/ent"
	"encoding/xml"
	"reflect"
	"testing"
)

// TestGenTests is a unit test for the GenTests function.
func TestGenTests(t *testing.T) {
	ovals := []*ent.Oval{
		&ent.Oval{
			ID:       "oval:cn.ctyun.ctyunos:def:20210207",
			TestList: "oval:cn.ctyun.ctyunos:tst:300000000004 oval:cn.ctyun.ctyunos:tst:300000000005 oval:cn.ctyun.ctyunos:tst:300000000006 oval:cn.ctyun.ctyunos:tst:300000000007 oval:cn.ctyun.ctyunos:tst:300000000008 oval:cn.ctyun.ctyunos:tst:300000000009",
		},
		&ent.Oval{
			ID:       "oval:cn.ctyun.ctyunos:def:20210208",
			TestList: "oval:cn.ctyun.ctyunos:tst:300000000010",
		},
	}

	expectedTests := Tests{
		XMLName:      xml.Name{Local: "tests"},
		RPMinfoTests: GenRpmInfoTests(ovals),
	}

	tests := GenTests(ovals)

	if !reflect.DeepEqual(tests, expectedTests) {
		t.Errorf("GenTests() = %v, expected %v", tests, expectedTests)
	}
}
