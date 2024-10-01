package ovaldefinitions

import (
	"ct_oval_tool/pkg/ovalxml/defintions"
	"ct_oval_tool/pkg/ovalxml/generator"
	"ct_oval_tool/pkg/ovalxml/objects"
	"ct_oval_tool/pkg/ovalxml/states"
	"ct_oval_tool/pkg/ovalxml/tests"
	"encoding/xml"
)

// 定义 OVAL 结构
type OvalDefinitions struct {
	XMLName           xml.Name                    `xml:"oval_definitions"`
	XMLNS             string                      `xml:"xmlns,attr"`
	OVAL              string                      `xml:"xmlns:oval,attr"`
	OVALDEF           string                      `xml:"xmlns:oval-def,attr"`
	UNIXDEF           string                      `xml:"xmlns:unix-def,attr"`
	REDDEF            string                      `xml:"xmlns:red-def,attr"`
	INDDEF            string                      `xml:"xmlns:ind-def,attr"`
	XSI               string                      `xml:"xmlns:xsi,attr"`
	XSISchemaLocation string                      `xml:"xsi:schemaLocation,attr"`
	Generator         generator.OvalGenerator     `xml:"generator"`
	Definition        []defintions.OvalDefinition `xml:"definitions>definition"`
	Tests             tests.Tests                 `xml:"tests"`
	Objects           objects.Objects             `xml:"objects"`
	States            states.States               `xml:"states"`
}
