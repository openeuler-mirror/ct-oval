package objects

import (
	"ct_oval_tool/pkg/ent"
	"encoding/xml"
)

// Objects 定义
type Objects struct {
	XMLName        xml.Name        `xml:"objects"`
	RPMinfoObjects []RPMinfoObject `xml:"rpminfo_object"`
}

func GenObjects(ovals []*ent.Oval) Objects {
	// 创建 RPMinfoObject 切片
	rpmObjects := GenRPMinfoObjects(ovals)

	// 创建一个新的 Objects 结构
	ovalObjects := Objects{
		RPMinfoObjects: rpmObjects,
	}

	return ovalObjects
}
