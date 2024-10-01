package states

import (
	"context"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/state"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"strings"
)

// 定义 StateSpec 结构体
type StateSpec struct {
	XMLName   xml.Name `xml:""`
	DataType  string   `xml:"datatype,attr,omitempty"`
	Operation string   `xml:"operation,attr,omitempty"`
	Text      string   `xml:",chardata"`
}

// 定义 RPMinfoState 结构体
type RPMinfoState struct {
	XMLName    xml.Name    `xml:"rpminfo_state"`
	XMLNS      string      `xml:"xmlns,attr"`
	ID         string      `xml:"id,attr"`
	Version    string      `xml:"version,attr"`
	PlatVerion []StateSpec `xml:"version,omitempty"`
	Arch       []StateSpec `xml:"arch,omitempty"`
	EVR        []StateSpec `xml:"evr,omitempty"`
	//SignatureKeyID   string   `xml:"signature_keyid,omitempty"`
	//VersionOperation string   `xml:"version>operation,omitempty"`
	//ArchOperation    string   `xml:"arch>operation,omitempty"`
	//EVR              string   `xml:"evr,omitempty"`
}

func GenRPMinfoStates(ovals []*ent.Oval) []RPMinfoState {
	var states []RPMinfoState
	db, _ := common.ConnectDB()
	defer db.Close()
	//填入所有2级(product)和1级(arch)，这里可能会多出无关的product和arch，但不影响测试。
	rets, _ := db.State.Query().Where(state.Or(state.StateIDContains("oval:cn.ctyun.ctyunos:ste:2"), state.StateIDContains("oval:cn.ctyun.ctyunos:ste:1"))).All(context.Background())
	for _, ret := range rets {
		var rpminfoState = RPMinfoState{
			XMLNS:   common.OvalRedDef,
			ID:      ret.StateID,
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{{
				XMLName:   xml.Name{Local: ret.Tag},
				DataType:  ret.Datatype,
				Operation: ret.Operation,
				Text:      ret.Value,
			}},
		}
		states = append(states, rpminfoState)
	}
	//填入3级state
	statelist := []string{}
	for _, oval := range ovals {
		statelist = append(statelist, strings.Split(oval.StateList, " ")...)
	}
	statelist = common.RemoveDuplication(statelist)
	for _, statevalue := range statelist {
		ret, _ := db.State.Query().Where(state.ValueEQ(statevalue)).First(context.Background())
		if ret == nil {
			println("Warning: ret is nil when statevalue is ", statevalue)
			continue
		}
		var rpminfoState = RPMinfoState{
			XMLNS:   common.OvalRedDef,
			ID:      ret.StateID,
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{{
				XMLName:   xml.Name{Local: ret.Tag},
				DataType:  ret.Datatype,
				Operation: ret.Operation,
				Text:      ret.Value,
			}},
		}
		states = append(states, rpminfoState)
	}
	return states
}
