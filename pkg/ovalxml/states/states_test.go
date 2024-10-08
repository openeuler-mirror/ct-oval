package states

import (
	"ct_oval_tool/pkg/ent"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenStates(t *testing.T) {
	// 创建测试数据
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

	// 调用函数生成结果
	result := GenStates(ovals)

	// 验证结果是否符合预期
	expected := States{
		RPMinfoStates: GenRPMinfoStates(ovals),
	}
	assert.Equal(t, expected, result)
}
