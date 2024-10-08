package objects

import (
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ovalxml/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenRPMinfoObjects tests the GenRPMinfoObjects function.
func TestGenRPMinfoObjects(t *testing.T) {
	// Prepare test data
	ovals := []*ent.Oval{
		&ent.Oval{
			ObjectList: "ImageMagick ImageMagick-c++ ImageMagick-c++-devel ImageMagick-devel ImageMagick-help ImageMagick-perl",
		},
		&ent.Oval{
			ObjectList: "golang",
		},
	}

	// Call the function under test
	objects := GenRPMinfoObjects(ovals)

	// Assert the result
	assert.Len(t, objects, 8)
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:100000000001",
		Version: common.OvalVersion,
		Name:    "ctyunos-release",
	}, objects[0])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000001",
		Version: common.OvalVersion,
		Name:    "ImageMagick",
	}, objects[1])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000002",
		Version: common.OvalVersion,
		Name:    "ImageMagick-c++",
	}, objects[2])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000003",
		Version: common.OvalVersion,
		Name:    "ImageMagick-c++-devel",
	}, objects[3])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000004",
		Version: common.OvalVersion,
		Name:    "ImageMagick-devel",
	}, objects[4])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000005",
		Version: common.OvalVersion,
		Name:    "ImageMagick-help",
	}, objects[5])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000006",
		Version: common.OvalVersion,
		Name:    "ImageMagick-perl",
	}, objects[6])
	assert.Equal(t, RPMinfoObject{
		XMLNS:   common.OvalRedDef,
		ID:      "oval:cn.ctyun.ctyunos:obj:300000000007",
		Version: common.OvalVersion,
		Name:    "golang",
	}, objects[7])
}
