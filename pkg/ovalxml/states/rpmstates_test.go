package states

import (
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenRPMinfoStates(t *testing.T) {
	ovals := []*ent.Oval{
		&ent.Oval{
			ID:        "oval:cn.ctyun.ctyunos:def:20210207",
			StateList: "6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2 6.9.12.86-4.ctl2",
		},
		&ent.Oval{
			ID:        "oval:cn.ctyun.ctyunos:def:20210208",
			StateList: "1.15.7-33.ctl2",
		},
	}
	states := GenRPMinfoStates(ovals)
	expectedStates := []RPMinfoState{
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:200000000001",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "version"},
					DataType:  "string",
					Operation: "pattern match",
					Text:      "2.0.1",
				},
			},
		},
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:200000000002",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "version"},
					DataType:  "string",
					Operation: "pattern match",
					Text:      "23.01",
				},
			},
		},
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:100000000001",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "arch"},
					DataType:  "string",
					Operation: "pattern match",
					Text:      "x86_64",
				},
			},
		},
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:100000000002",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "arch"},
					DataType:  "string",
					Operation: "pattern match",
					Text:      "aarch64",
				},
			},
		},
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:300000000004",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "evr"},
					DataType:  "evr_string",
					Operation: "less than",
					Text:      "6.9.12.86-4.ctl2",
				},
			},
		},
		{
			XMLNS:   common.OvalRedDef,
			ID:      "oval:cn.ctyun.ctyunos:ste:300000000005",
			Version: common.OvalVersion,
			PlatVerion: []StateSpec{
				{
					XMLName:   xml.Name{Local: "evr"},
					DataType:  "evr_string",
					Operation: "less than",
					Text:      "1.15.7-33.ctl2",
				},
			},
		},
	}
	assert.Equal(t, expectedStates, states)
}
