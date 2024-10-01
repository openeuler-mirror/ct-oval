package objects

import (
	"context"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/object"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"strings"
)

// 定义 RPMinfoObject 结构体
type RPMinfoObject struct {
	XMLName xml.Name `xml:"rpminfo_object"`
	XMLNS   string   `xml:"xmlns,attr"`
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version,attr"`
	Name    string   `xml:"name"`
}

func GenRPMinfoObjects(ovals []*ent.Oval) []RPMinfoObject {
	var objects []RPMinfoObject
	db, _ := common.ConnectDB()
	defer db.Close()
	//填入2级(product)和1级(arch)
	rets, _ := db.Object.Query().Where(object.Or(object.ObjectIDContains("oval:cn.ctyun.ctyunos:obj:2"), object.ObjectIDContains("oval:cn.ctyun.ctyunos:obj:1"))).All(context.Background())
	for _, ret := range rets {
		var rpminfoObject = RPMinfoObject{
			XMLNS:   common.OvalRedDef,
			ID:      ret.ObjectID,
			Version: common.OvalVersion,
			Name:    ret.Name,
		}
		objects = append(objects, rpminfoObject)
	}
	//填入3级object
	objectlist := []string{}
	for _, oval := range ovals {
		objectlist = append(objectlist, strings.Split(oval.ObjectList, " ")...)
	}
	objectlist = common.RemoveDuplication(objectlist)
	for _, objectname := range objectlist {
		ret, _ := db.Object.Query().Where(object.NameEQ(objectname)).First(context.Background())
		if ret == nil {
			println("Warning: ret is nil when objectname is ", objectname)
			continue
		}
		var rpminfoObject = RPMinfoObject{
			XMLNS:   common.OvalRedDef,
			ID:      ret.ObjectID,
			Version: common.OvalVersion,
			Name:    ret.Name,
		}
		objects = append(objects, rpminfoObject)
	}
	return objects
}
