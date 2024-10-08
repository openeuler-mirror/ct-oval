package defintions

import (
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ovalxml/common"
	"fmt"
	"reflect"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestGenOvalDefinition(t *testing.T) {
	oval := &ent.Oval{
		ID:          "1",
		Ovalversion: "1.0",
		Class:       "oval",
		Title:       "Test Title",
		CveList:     "CVE-2020-27762 CVE-2020-27766 CVE-2020-27761 CVE-2020-27767 CVE-2020-27770 CVE-2020-27759 CVE-2020-27760 CVE-2020-27765 CVE-2020-29599 CVE-2020-27764",
		ArchList:    "x86_64 aarch64",
		TestList:    "oval:cn.ctyun.ctyunos:tst:300000000004 oval:cn.ctyun.ctyunos:tst:300000000005 oval:cn.ctyun.ctyunos:tst:300000000006 oval:cn.ctyun.ctyunos:tst:300000000007 oval:cn.ctyun.ctyunos:tst:300000000008 oval:cn.ctyun.ctyunos:tst:300000000009",
		ObjectList:  "ImageMagick ImageMagick-c++ ImageMagick-c++-devel ImageMagick-devel ImageMagick-help ImageMagick-perl",
		StateList:   "6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2",
		Family:      "unix",
		Platform:    "CTyunOS Linux",
		Description: "Test Description",
		Severity:    "Critical",
		Copyright:   "Test Copyright",
		Issuedate:   "2021-01-01",
	}
	db, _ := common.ConnectDB()
	defer db.Close()

	// Calling the function to be tested
	definition := GenOvalDefinition(oval)

	// Asserting the expected output with the actual output
	// expectedDefinition := OvalDefinition{
	// 	ID:      "1",
	// 	Version: "1.0",
	// 	Class:   "oval",
	// 	Metadata: OvalMetadata{
	// 		Title: "Test Title",
	// 		Affected: OvalAffected{
	// 			Family:   "Test Family",
	// 			Platform: "Test Platform",
	// 		},
	// 		Reference: []OvalReference{
	// 			{Source: common.SaSource, RefID: "Test", RefURL: common.SaRef + "Test"},
	// 			{Source: "CVE", RefID: "CVE-1", RefURL: "CVE-1 URL"},
	// 			{Source: "CVE", RefID: "CVE-2", RefURL: "CVE-2 URL"},
	// 		},
	// 		Description: "Test Description",
	// 		Advisory: OvalAdvisory{
	// 			Severity: "Critical",
	// 			Rights:   "Test Copyright",
	// 			Issued:   "2021-01-01",
	// 		},
	// 	},
	// 	Criteria: OvalCriteria{
	// 		Operator: "AND",
	// 		Criterion: []OvalCriterion{
	// 			{
	// 				TestRef: "oval:cn.ctyun.ctyunos:tst:200000000001",
	// 				Comment: "CTyunOS Linux is installed",
	// 			},
	// 		},
	// 		Criteria: []OvalCriteria{
	// 			{
	// 				Operator: "OR",
	// 				Criteria: []OvalCriteria{
	// 					{
	// 						Operator: "AND",
	// 						Criterion: []OvalCriterion{
	// 							{
	// 								TestRef: "test1",
	// 								Comment: "Test Comment 1",
	// 							},
	// 						},
	// 					},
	// 					{
	// 						Operator: "AND",
	// 						Criterion: []OvalCriterion{
	// 							{
	// 								TestRef: "test2",
	// 								Comment: "Test Comment 2",
	// 							},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		},
	// 	},
	// }
	ret := fmt.Sprintf("%+v", reflect.TypeOf(definition))
	fmt.Print(ret, "\n +++++++++++++++++ \n", t)
	assert.Equal(t, "defintions.OvalDefinition", ret)
}

func TestGenOvalDefinitions(t *testing.T) {
	ovals := []*ent.Oval{
		&ent.Oval{
			ID:          "1",
			Ovalversion: "1.0",
			Class:       "oval",
			Title:       "Test Title",
			CveList:     "CVE-2020-27762 CVE-2020-27766 CVE-2020-27761 CVE-2020-27767 CVE-2020-27770 CVE-2020-27759 CVE-2020-27760 CVE-2020-27765 CVE-2020-29599 CVE-2020-27764",
			ArchList:    "x86_64 aarch64",
			TestList:    "oval:cn.ctyun.ctyunos:tst:300000000004 oval:cn.ctyun.ctyunos:tst:300000000005 oval:cn.ctyun.ctyunos:tst:300000000006 oval:cn.ctyun.ctyunos:tst:300000000007 oval:cn.ctyun.ctyunos:tst:300000000008 oval:cn.ctyun.ctyunos:tst:300000000009",
			ObjectList:  "ImageMagick ImageMagick-c++ ImageMagick-c++-devel ImageMagick-devel ImageMagick-help ImageMagick-perl",
			StateList:   "6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2",
			Family:      "unix",
			Platform:    "CTyunOS Linux",
			Description: "Test Description",
			Severity:    "Critical",
			Copyright:   "Test Copyright",
			Issuedate:   "2021-01-01",
		},
	}

	definitions := GenOvalDefinitions(ovals)
	ret := fmt.Sprintf("%+v", reflect.TypeOf(definitions))
	assert.Equal(t, "[]defintions.OvalDefinition", ret)
}
