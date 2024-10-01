package tests

import (
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ovalxml/common"
	"testing"
)

func TestGenRpmInfoTests(t *testing.T) {
	db, _ := common.ConnectDB()
	defer db.Close()

	ovals := []*ent.Oval{
		&ent.Oval{
			ID:       "oval:cn.ctyun.ctyunos:def:20210207",
			TestList: "oval:cn.ctyun.ctyunos:tst:300000000004 oval:cn.ctyun.ctyunos:tst:300000000005 oval:cn.ctyun.ctyunos:tst:300000000006 oval:cn.ctyun.ctyunos:tst:300000000007 oval:cn.ctyun.ctyunos:tst:300000000008 oval:cn.ctyun.ctyunos:tst:300000000009",
		},
		&ent.Oval{
			ID:       "oval:cn.ctyun.ctyunos:def:20210208",
			TestList: "oval:cn.ctyun.ctyunos:tst:300000000009",
		},
	}

	tests := GenRpmInfoTests(ovals)

	expectedTests := []RPMinfoTest{
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:200000000001",
			Version: common.OvalVersion,
			Comment: "CTyunOS 2.0.1 is installed",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:100000000001",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:200000000001",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:200000000002",
			Version: common.OvalVersion,
			Comment: "CTyunOS 23.01 is installed",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:100000000001",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:200000000002",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:100000000001",
			Version: common.OvalVersion,
			Comment: "CTyunOS Linux arch is x86_64",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:100000000001",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:100000000001",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:100000000002",
			Version: common.OvalVersion,
			Comment: "CTyunOS Linux arch is aarch64",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:100000000001",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:100000000002",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000004",
			Version: common.OvalVersion,
			Comment: "ImageMagick is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000001",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000005",
			Version: common.OvalVersion,
			Comment: "ImageMagick-c++ is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000002",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000006",
			Version: common.OvalVersion,
			Comment: "ImageMagick-c++-devel is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000003",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000007",
			Version: common.OvalVersion,
			Comment: "ImageMagick-devel is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000004",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000008",
			Version: common.OvalVersion,
			Comment: "ImageMagick-help is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000005",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
		{
			ID:      "oval:cn.ctyun.ctyunos:tst:300000000009",
			Version: common.OvalVersion,
			Comment: "ImageMagick-perl is earlier than 6.9.12.86-4.ctl2",
			Check:   "at least one",
			XMLNS:   common.OvalRedDef,
			Object: Object{
				ObjectRef: "oval:cn.ctyun.ctyunos:obj:300000000006",
			},
			State: State{
				StateRef: "oval:cn.ctyun.ctyunos:ste:300000000004",
			},
		},
	}

	if len(tests) != len(expectedTests) {
		t.Errorf("Expected %d tests, but got %d", len(expectedTests), len(tests))
	}

	for i, test := range tests {
		if test.ID != expectedTests[i].ID {
			t.Errorf("Expected test ID: %s, but got: %s", expectedTests[i].ID, test.ID)
		}
		if test.Version != expectedTests[i].Version {
			t.Errorf("Expected test Version: %s, but got: %s", expectedTests[i].Version, test.Version)
		}
		if test.Comment != expectedTests[i].Comment {
			t.Errorf("Expected test Comment: %s, but got: %s", expectedTests[i].Comment, test.Comment)
		}
		if test.Check != expectedTests[i].Check {
			t.Errorf("Expected test Check: %s, but got: %s", expectedTests[i].Check, test.Check)
		}
		if test.XMLNS != expectedTests[i].XMLNS {
			t.Errorf("Expected test XMLNS: %s, but got: %s", expectedTests[i].XMLNS, test.XMLNS)
		}
		if test.Object.ObjectRef != expectedTests[i].Object.ObjectRef {
			t.Errorf("Expected test Object.ObjectRef: %s, but got: %s", expectedTests[i].Object.ObjectRef, test.Object.ObjectRef)
		}
		if test.State.StateRef != expectedTests[i].State.StateRef {
			t.Errorf("Expected test State.StateRef: %s, but got: %s", expectedTests[i].State.StateRef, test.State.StateRef)
		}
	}
}
