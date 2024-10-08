package defintions

import (
	"context"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/cveref"
	"ct_oval_tool/pkg/ent/test"
	"ct_oval_tool/pkg/logger"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"fmt"
	"strings"
)

var log = logger.GetLogger()

type OvalDefinition struct {
	XMLName  xml.Name     `xml:"definition"`
	ID       string       `xml:"id,attr"`
	Version  string       `xml:"version,attr"`
	Class    string       `xml:"class,attr"`
	Metadata OvalMetadata `xml:"metadata"`
	Criteria OvalCriteria `xml:"criteria"`
}

// OvalAdvisory 定义 Advisory 结构
type OvalAdvisory struct {
	XMLName  xml.Name `xml:"advisory"`
	Severity string   `xml:"severity"`
	Rights   string   `xml:"rights"`
	Issued   string   `xml:"issued>date"`
}

// OvalAffected 定义 Affected 结构
type OvalAffected struct {
	XMLName  xml.Name `xml:"affected"`
	Family   string   `xml:"family,attr"`
	Platform string   `xml:"platform"`
}

// OvalReference 定义 Reference 结构
type OvalReference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
}

type OvalMetadata struct {
	XMLName     xml.Name        `xml:"metadata"`
	Title       string          `xml:"title"`
	Affected    OvalAffected    `xml:"affected"`
	Reference   []OvalReference `xml:"reference"`
	Description string          `xml:"description"`
	Advisory    OvalAdvisory    `xml:"advisory"`
}

// 定义 Criterion 结构
type OvalCriterion struct {
	XMLName xml.Name `xml:"criterion"`
	TestRef string   `xml:"test_ref,attr"`
	Comment string   `xml:"comment,attr,omitempty"`
}

// OvalCriteria 定义 Criteria 结构
type OvalCriteria struct {
	Operator  string          `xml:"operator,attr"`
	Criterion []OvalCriterion `xml:"criterion,omitempty"`
	Criteria  []OvalCriteria  `xml:"criteria,omitempty"`
}

// GenOvalDefinition 将公告信息转化为输出xml的结构体
func GenOvalDefinition(oval *ent.Oval) OvalDefinition {
	// 填充 Reference 列表数据
	titles := strings.Split(oval.Title, " ")
	var references []OvalReference
	references = append(references, OvalReference{Source: common.SaSource, RefID: titles[0], RefURL: common.SaRef + titles[0]})
	db, _ := common.ConnectDB()
	defer db.Close()
	for _, cveid := range strings.Split(oval.CveList, " ") {
		cve, _ := db.Cveref.Query().Where(cveref.RefIDEQ(cveid)).First(context.Background())
		referenceSecNotice := OvalReference{
			Source: "CVE",
			RefID:  cve.RefID,
			RefURL: cve.RefURL,
		}
		references = append(references, referenceSecNotice)
	}

	// 处理Criterias
	// 1. 生成顶层(层级2)的测试，关系是 AND
	var tid int
	var tproduct string
	for id, product := range strings.Split(common.Productlist, " ") {
		if oval.Platform == "ctyunos-"+product {
			tid = id + 1
			tproduct = product
			break
		}
	}
	var productOvalCriterion = OvalCriterion{
		TestRef: fmt.Sprintf("oval:cn.ctyun.ctyunos:tst:20000000000%d", tid),
		Comment: "CTyunOS " + tproduct + " is installed",
	}
	var archCriterias []OvalCriteria
	for id, arch := range strings.Split(oval.ArchList, " ") {
		//2. 生成次层(层级1)的测试，arch间关系是 OR
		var archOvalCriterion = OvalCriterion{
			TestRef: fmt.Sprintf("oval:cn.ctyun.ctyunos:tst:10000000000%d", id+1),
			Comment: "CTyunOS Linux arch is " + arch,
		}
		var pkgOvalCriteriaItems []OvalCriteria
		for _, test_string := range strings.Split(oval.TestList, " ") {
			//3. 生成底层(层级0)的测试，pkg间关系是 OR
			Test, _ := db.Test.Query().Where(test.TestIDEQ(test_string)).First(context.Background())
			var ovalCriterion = []OvalCriterion{{
				TestRef: Test.TestID,
				Comment: Test.Comment,
			}}
			//4. 单个pkg的测试内的关系是 AND，目的是为checksum做预留
			pkgOvalCriteriaItem := OvalCriteria{
				Operator:  "AND",
				Criterion: ovalCriterion,
			}
			pkgOvalCriteriaItems = append(pkgOvalCriteriaItems, pkgOvalCriteriaItem)
		}
		// 多个pkg间关系为 OR， 对应步骤3
		pkgsCriteriaItems := []OvalCriteria{{
			Operator: "OR",
			Criteria: pkgOvalCriteriaItems,
		}}
		// 每个arch中的criterion（1级测试）和criteria（3级测试）的关系是 AND
		var archCriteriaItems = OvalCriteria{
			Operator:  "AND",
			Criterion: []OvalCriterion{archOvalCriterion},
			Criteria:  pkgsCriteriaItems,
		}
		archCriterias = append(archCriterias, archCriteriaItems)
	}
	// 多个arch关系 OR，对应步骤2
	archCriteriaItems := []OvalCriteria{{
		Operator: "OR",
		Criteria: archCriterias,
	}}
	// 组装最终数据结构体
	var productCriteriaItems = OvalCriteria{
		Operator:  "AND",
		Criterion: []OvalCriterion{productOvalCriterion},
		Criteria:  archCriteriaItems,
	}

	// 创建OVAL 定义信息
	definition := OvalDefinition{
		ID:      oval.ID,
		Version: oval.Ovalversion,
		Class:   oval.Class,
		Metadata: OvalMetadata{
			Title: oval.Title,
			Affected: OvalAffected{
				Family:   oval.Family,
				Platform: oval.Platform,
			},
			Reference:   references,
			Description: oval.Description,
			Advisory: OvalAdvisory{
				Severity: oval.Severity,
				Rights:   oval.Copyright,
				Issued:   oval.Issuedate,
			},
		},
		Criteria: productCriteriaItems,
	}
	log.Debug("OVAL ", oval.ID, " generated successfully.")
	return definition
}

// 根据输入的ovals生成definitions部分的结构体数据
func GenOvalDefinitions(ovals []*ent.Oval) []OvalDefinition {
	var definitions []OvalDefinition
	for _, oval := range ovals {
		definition := GenOvalDefinition(oval)
		definitions = append(definitions, definition)
	}
	log.Debug("all OVAL definitions generated successfully.")
	return definitions
}
