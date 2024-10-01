package ovalxml

import (
	"ct_oval_tool/cmd/flag"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ovalxml/common"
	"ct_oval_tool/pkg/ovalxml/defintions"
	"ct_oval_tool/pkg/ovalxml/generator"
	"ct_oval_tool/pkg/ovalxml/objects"
	"ct_oval_tool/pkg/ovalxml/ovaldefinitions"
	"ct_oval_tool/pkg/ovalxml/states"
	"ct_oval_tool/pkg/ovalxml/tests"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGenOval(t *testing.T) {
	ovals := []*ent.Oval{
		{
			ID:         "oval:cn.ctyun.ctyunos:def:20210207",
			ObjectList: "ImageMagick ImageMagick-c++ ImageMagick-c++-devel ImageMagick-devel ImageMagick-help ImageMagick-perl",
			StateList:  "6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2",
			TestList:   "oval:cn.ctyun.ctyunos:tst:300000000004 oval:cn.ctyun.ctyunos:tst:300000000005 oval:cn.ctyun.ctyunos:tst:300000000006 oval:cn.ctyun.ctyunos:tst:300000000007 oval:cn.ctyun.ctyunos:tst:300000000008 oval:cn.ctyun.ctyunos:tst:300000000009",
			CveList:    "CVE-2020-27762 CVE-2020-27766 CVE-2020-27761 CVE-2020-27767 CVE-2020-27770 CVE-2020-27759 CVE-2020-27760 CVE-2020-27765 CVE-2020-29599 CVE-2020-27764",
		},
	} // Fill with test data

	expected := ovaldefinitions.OvalDefinitions{
		XMLNS:             common.OvalDef,
		OVAL:              common.OvalCommon,
		OVALDEF:           common.OvalDef,
		UNIXDEF:           common.OvalUnixDef,
		REDDEF:            common.OvalRedDef,
		INDDEF:            common.OvalIndDef,
		XSI:               common.XmlSchemaInstance,
		XSISchemaLocation: common.XSISchemaLocation,
		Generator:         generator.GenGenerator(),
		Definition:        defintions.GenOvalDefinitions(ovals),
		Tests:             tests.GenTests(ovals),
		Objects:           objects.GenObjects(ovals),
		States:            states.GenStates(ovals),
	}
	result := GenOval(ovals)
	assert.Equal(t, expected, result)
}

func TestGeneratedOvalXml(t *testing.T) {
	// Set up test case
	viper.Set(flag.KeyDateFrom, "2022-01-01")
	viper.Set(flag.KeyDateTo, "2022-01-31")
	viper.Set(flag.KeyProduct, "ImageMagick")
	viper.Set(flag.KeyOutputFile, "CTyunos-oval.xml")

	// Run the function to be tested
	err := GeneratedOvalXml()

	// Assert the result
	assert.NoError(t, err)
	// Check if the file is created
	_, err = os.Stat("CTyunos-oval.xml")
	assert.False(t, os.IsNotExist(err))
	// TODO: Add more assertions for the content of the generated XML file
}
