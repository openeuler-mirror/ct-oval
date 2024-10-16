package tests

import (
	"context"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/test"
	"ct_oval_tool/pkg/logger"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"strings"
)

var log = logger.GetLogger()

// 定义 RPMinfoTest 结构
type RPMinfoTest struct {
	XMLName xml.Name `xml:"rpminfo_test"`
	XMLNS   string   `xml:"xmlns,attr"`
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version,attr"`
	Comment string   `xml:"comment,attr"`
	Check   string   `xml:"check,attr"`
	Object  Object   `xml:"object"`
	State   State    `xml:"state"`
}

// 定义 Object 结构
type Object struct {
	//XMLName   xml.Name `xml:"object"`
	ObjectRef string `xml:"object_ref,attr"`
}

// 定义 State 结构
type State struct {
	//XMLName  xml.Name `xml:"state"`
	StateRef string `xml:"state_ref,attr"`
}

func GenRpmInfoTests(ovals []*ent.Oval) []RPMinfoTest {
	// 	var references []OvalReference
	// references = append(references, OvalReference{Source: common.SaSource, RefID: titles[0], RefURL: common.SaRef + titles[0]})
	db, _ := common.ConnectDB()
	defer db.Close()
	var tests []RPMinfoTest
	//填入2级(product)和1级测试(arch)
	rets, _ := db.Test.Query().Where(test.Or(test.TestIDContains("oval:cn.ctyun.ctyunos:tst:2"), test.TestIDContains("oval:cn.ctyun.ctyunos:tst:1"))).All(context.Background())
	//log.Debug("Test level2 and level1 contents are: ", rets)
	for _, ret := range rets {
		var rpminfoObject = RPMinfoTest{
			ID:      ret.TestID,
			Version: common.OvalVersion,
			Comment: ret.Comment,
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: ret.ObjectID,
			},
			State: State{
				StateRef: ret.StateID,
			},
		}
		tests = append(tests, rpminfoObject)
	}
	testlist := []string{}
	for _, oval := range ovals {
		testlist = append(testlist, strings.Split(oval.TestList, " ")...)
	}
	testlist = common.RemoveDuplication(testlist)
	for _, testid := range testlist {
		ret, _ := db.Test.Query().Where(test.TestIDEQ(testid)).First(context.Background())
		//填入3级测试package is earlier than
		var rpminfoObject = RPMinfoTest{
			ID:      ret.TestID,
			Version: common.OvalVersion,
			Comment: ret.Comment,
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: ret.ObjectID,
			},
			State: State{
				StateRef: ret.StateID,
			},
		}
		tests = append(tests, rpminfoObject)
	}
	return tests
}
