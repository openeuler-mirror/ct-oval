package tests

import (
	"ct_oval_tool/pkg/ent"
	"encoding/xml"
)

// Tests 定义 RPMinfoTest 结构
type Tests struct {
	XMLName      xml.Name      `xml:"tests"`
	RPMinfoTests []RPMinfoTest `xml:"rpminfo_test"`
}

func GenTests(ovals []*ent.Oval) Tests {
	// 创建 tests 切片
	tests := GenRpmInfoTests(ovals)

	// 创建一个新的 OVAL 结构
	ovalTests := Tests{
		XMLName:      xml.Name{Local: "tests"},
		RPMinfoTests: tests,
	}
	return ovalTests
}
