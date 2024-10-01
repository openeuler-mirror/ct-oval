package states

import (
	"ct_oval_tool/pkg/ent"
	"encoding/xml"
)

// States 定义
type States struct {
	XMLName       xml.Name       `xml:"states"`
	RPMinfoStates []RPMinfoState `xml:"rpminfo_state"`
}

func GenStates(ovals []*ent.Oval) States {
	// 创建 RPMinfoState 切片
	states := GenRPMinfoStates(ovals)

	// 创建一个新的 States 结构
	ovalStates := States{
		RPMinfoStates: states,
	}

	return ovalStates
}
