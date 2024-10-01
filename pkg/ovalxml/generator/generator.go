package generator

import (
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/xml"
	"time"
)

// OvalGenerator 定义 Generator 结构
type OvalGenerator struct {
	XMLName        xml.Name `xml:"generator"`
	ProductName    string   `xml:"oval:product_name"`
	ProductVersion string   `xml:"oval:product_version"`
	SchemaVersion  string   `xml:"oval:schema_version"`
	Timestamp      string   `xml:"oval:timestamp"`
}

func GenGenerator() OvalGenerator {
	// 创建 Generator 结构体实例
	// 注意：这里使用的是common里设的Product信息，而没有使用数据库里的
	generator := OvalGenerator{
		ProductName:    common.ProductName,
		ProductVersion: common.ProductVersion,
		SchemaVersion:  common.SchemaVersion,
		Timestamp:      time.Now().Format(time.RFC3339),
	}

	return generator
}
