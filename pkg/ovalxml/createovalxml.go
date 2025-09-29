package ovalxml

import (
	"bufio"
	"context"
	"ct_oval_tool/cmd/flag"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/oval"
	"ct_oval_tool/pkg/ent/predicate"
	"ct_oval_tool/pkg/logger"
	"ct_oval_tool/pkg/ovalxml/common"
	"ct_oval_tool/pkg/ovalxml/defintions"
	"ct_oval_tool/pkg/ovalxml/generator"
	"ct_oval_tool/pkg/ovalxml/objects"
	"ct_oval_tool/pkg/ovalxml/ovaldefinitions"
	"ct_oval_tool/pkg/ovalxml/states"
	"ct_oval_tool/pkg/ovalxml/tests"
	"encoding/xml"
	"fmt"
	"os"
	"unicode"

	"github.com/spf13/viper"
)

var log = logger.GetLogger()

// GenOval 生成 OVAL 定义集合。
// 该函数不接受参数，返回一个 ovaldefinitions.OvalDefinitions 结构体实例。
// 输出数据有5个： 一个生成者（固定）、一个公告信息、一个OVAL定义、一个OVAL测试、一个OVAL对象、一个OVAL状态
func GenOval(ovals []*ent.Oval) ovaldefinitions.OvalDefinitions {
	// 初始化生成者信息，这部分是固定信息，和oval数据库无交互
	creater := generator.GenGenerator()

	// 创建 OVAL 定义集合
	definitioninfo := defintions.GenOvalDefinitions(ovals)

	// 生成所匹配的 OVAL 测试
	ovalTests := tests.GenTests(ovals)

	// 生成所匹配的 OVAL 对象
	ovalObjects := objects.GenObjects(ovals)

	// 生成所匹配的 OVAL 状态
	ovalStates := states.GenStates(ovals)

	// 组装 OVAL 定义集合的各个部分
	ovalDef := ovaldefinitions.OvalDefinitions{
		XMLNS:             common.OvalDef,
		OVAL:              common.OvalCommon,
		OVALDEF:           common.OvalDef,
		UNIXDEF:           common.OvalUnixDef,
		REDDEF:            common.OvalRedDef,
		INDDEF:            common.OvalIndDef,
		XSI:               common.XmlSchemaInstance,
		XSISchemaLocation: common.XSISchemaLocation,
		Generator:         creater,
		Definition:        definitioninfo,
		Tests:             ovalTests,
		Objects:           ovalObjects,
		States:            ovalStates,
	}
	return ovalDef
}

// 处理datefrom：4位数字补全为YYYY-01-01
func processDateFrom(datefrom string) string {
	if len(datefrom) != 4 {
		return datefrom
	}
	// 检查是否全为数字
	for _, c := range datefrom {
		if !unicode.IsDigit(c) {
			return datefrom
		}
	}
	return datefrom + "-01-01"
}

// 处理dateto：4位数字补全为YYYY-12-31
func processDateTo(dateto string) string {
	if len(dateto) != 4 {
		return dateto
	}
	// 检查是否全为数字
	for _, c := range dateto {
		if !unicode.IsDigit(c) {
			return dateto
		}
	}
	return dateto + "-12-31"
}

// GeneratedOvalXml 生成 OVAL 格式的 XML 文件。
// 该函数不接受参数，也不返回任何值。
// 主要步骤包括：
// 1. 依命令行flag查询符合条件的oval
// 2. 生成 OVAL 结构数据；
// 3. 将 OVAL 结构编码为 XML；
// 4. 追加 XML 头信息；
// 5. 将 XML 数据写入文件。
func GeneratedOvalXml() error {
	// 1. 依命令行flag查询符合条件的oval
	datefrom := processDateFrom(viper.GetString(flag.KeyDateFrom))
	dateto := processDateTo(viper.GetString(flag.KeyDateTo))
	product := viper.GetString(flag.KeyProduct)
	output := viper.GetString(flag.KeyOutputFile)
	db, err := common.ConnectDB()
	if err != nil {
		return fmt.Errorf("failed to connect database: %v", err)
	}
	defer db.Close()
	log.Debug("Output file is: ", output)
	log.Debug("Filters are: ", datefrom, dateto, product)
	filter := []predicate.Oval{oval.IssuedateGTE(datefrom)}
	if dateto != "" {
		log.Debug("DateTo is: ", dateto)
		filter = append(filter, oval.IssuedateLTE(dateto))
	}
	if product != "" {
		log.Debug("Only proceed product(platform): ", product)
		filter = append(filter, oval.PlatformEQ(product))
	}
	ovals, err := db.Oval.Query().Where(filter...).All(context.Background())
	//ovals, err := db.Oval.Query().All(context.Background())

	if err != nil {
		return fmt.Errorf("failed to query oval: %v", err)
	}

	// 2. 生成 oval 结构数据
	var ovalDef = GenOval(ovals)

	// 3. 将 OVAL 结构编码为 XML
	xmlData, err := xml.MarshalIndent(ovalDef, "", "  ")
	if err != nil {
		log.Error("Error marshalling XML: %v", err)
		return err
	}

	// 4. 追加xml头
	xmlData = append([]byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"), xmlData...)

	// 5. 将 XML 写入文件
	file, err := os.Create(output)
	if err != nil {
		log.Error("Error creating file: %v", err)
		return err
	}
	defer file.Close()

	// 使用 bufio.Writer 加速文件写入操作
	writer := bufio.NewWriter(file)
	_, err = writer.Write(xmlData)
	if err != nil {
		log.Error("Error writing to file: %v", err)
		return err
	}
	// 刷新缓冲区确保所有数据都写入文件
	err = writer.Flush()
	if err != nil {
		log.Error("Error flushing writer: %v", err)
		return err
	}
	log.Info("OVAL ", output, " generated successfully.")
	return nil
}
