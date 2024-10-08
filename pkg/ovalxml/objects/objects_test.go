package objects

import (
	"ct_oval_tool/pkg/ent"
	"strings"
	"testing"
)

func TestGenObjects(t *testing.T) {
	// 创建测试数据
	ovals := []*ent.Oval{
		&ent.Oval{
			ID:         "oval:cn.ctyun.ctyunos:def:20210207",
			ObjectList: "ImageMagick ImageMagick-c++ ImageMagick-c++-devel ImageMagick-devel ImageMagick-help ImageMagick-perl",
		},
		&ent.Oval{
			ID:         "oval:cn.ctyun.ctyunos:def:20210208",
			ObjectList: "golang",
		},
	}

	// 调用函数生成结果
	ovalObjects := GenObjects(ovals)

	// 验证结果是否符合预期
	objectslen := 0
	for _, oval := range ovals {
		objectslen += strings.Count(oval.ObjectList, " ") + 1
	}
	// Adding level 1 object (ctyunos is installed)
	objectslen += 1
	if len(ovalObjects.RPMinfoObjects) != objectslen {
		t.Errorf("GenObjects() returned %d RPMinfoObjects, expected %d", len(ovalObjects.RPMinfoObjects), objectslen)
	}
	for _, rpmObject := range ovalObjects.RPMinfoObjects {
		if !strings.Contains(rpmObject.ID, "oval:cn.ctyun.ctyunos:obj:") {
			t.Errorf("GenObjects() returned RPMinfoObject with ID %s, expected oval:cn.ctyun.ctyunos:obj:xxxx", rpmObject.ID)
		}
	}
}
