package securitynotice

import (
	"bytes"
	"context"
	"ct_oval_tool/cmd/flag"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/ent/cveref"
	"ct_oval_tool/pkg/ent/object"
	"ct_oval_tool/pkg/ent/oval"
	"ct_oval_tool/pkg/ent/state"
	"ct_oval_tool/pkg/ent/test"
	"ct_oval_tool/pkg/logger"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var log = logger.GetLogger()

type JsonSecurityNotice struct {
	ID                int    `json:"id"`
	SecurityNoticeNo  string `json:"security_notice_no"`
	NoticeURL         string `json:"notice_url"`
	Summary           string `json:"summary"`
	Type              int    `json:"type"`
	AffectedProduct   string `json:"affected_product"`
	AffectedComponent string `json:"affected_component"`
	AnnouncementTime  string `json:"announcement_time"`
	Description       string `json:"description"`
	Introduction      string `json:"introduction"`
	CVEList           []CVE  `json:"cve_list"`
	Files             []File `json:"files"`
	ReferenceList     []struct {
		URL string `json:"url"`
	} `json:"reference_list"`
	Subject string `json:"subject"`
}

type CVE struct {
	URL   string `json:"url"`
	CveID string `json:"cve_id"`
}

type File struct {
	Arch string    `json:"arch"`
	List []RpmFile `json:"list"`
}

type RpmFile struct {
	FileName string `json:"file_name"`
	Version  string `json:"version"`
	FileURL  string `json:"file_url"`
}

type Summarycontent struct {
	ID                int    `json:"id"`
	SecurityNoticeNo  string `json:"security_notice_no"`
	Summary           string `json:"summary"`
	Type              int    `json:"type"`
	AffectedProduct   string `json:"affected_product"`
	AffectedComponent string `json:"affected_component"`
	AnnouncementTime  string `json:"announcement_time"`
}

type CveSummary struct {
	Code int `json:"code"`
	Data struct {
		Count int              `json:"count"`
		List  []Summarycontent `json:"list"`
	} `json:"data"`
}

type HttpResponse struct {
	Code int                `json:"code"`
	Data JsonSecurityNotice `json:"data"`
}

func parseJSONData(data []byte) (JsonSecurityNotice, error) {
	var securityNotice JsonSecurityNotice
	err := json.Unmarshal(data, &securityNotice)
	if err != nil {
		return JsonSecurityNotice{}, fmt.Errorf("无法解析JSON: %v", err)
	}
	return securityNotice, nil
}

func parseJSONFile(filePath string) (JsonSecurityNotice, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return JsonSecurityNotice{}, fmt.Errorf("无法读取文件: %v", filePath)
	}
	return parseJSONData(data)
}

func printJsonSecurityNotice(securityNotice JsonSecurityNotice) {
	fmt.Println("ID:", securityNotice.ID)
	fmt.Println("Security Notice No:", securityNotice.SecurityNoticeNo)
	fmt.Println("Subject:", securityNotice.Subject)
	fmt.Println("Notice URL:", securityNotice.NoticeURL)
	fmt.Println("Summary:", securityNotice.Summary)
	fmt.Println("Type:", securityNotice.Type)
	fmt.Println("Affected Product:", securityNotice.AffectedProduct)
	fmt.Println("Affected Component:", securityNotice.AffectedComponent)
	fmt.Println("Announcement Time:", securityNotice.AnnouncementTime)
	fmt.Println("Description:", securityNotice.Description)
	fmt.Println("Introduction:", securityNotice.Introduction)
	fmt.Println("CVE List:")
	for _, cve := range securityNotice.CVEList {
		fmt.Println("  URL:", cve.URL)
		fmt.Println("  CVE ID:", cve.CveID)
	}
	fmt.Println("Files:")
	for _, file := range securityNotice.Files {
		fmt.Println("  Arch:", file.Arch)
		fmt.Println("  List:")
		for _, f := range file.List {
			fmt.Println("    File Name:", f.FileName)
			fmt.Println("    Version:", f.Version)
			fmt.Println("    File URL:", f.FileURL)
		}
	}
	fmt.Println("Reference List:")
	for _, ref := range securityNotice.ReferenceList {
		fmt.Println("  URL:", ref.URL)
	}
}

func WriteOval(sn SecurityNotice, client *ent.Client) (*ent.Oval, error) {
	now := time.Now()
	year, month, day := now.Date()
	hour, minute, second := now.Clock()
	CreatedAt := time.Date(year, month, day, hour, minute, second, 0, time.Local)
	oval, err := client.Oval.
		Create().
		SetProductname(sn.ProductName).
		SetProductversion(sn.ProductVersion).
		SetSchemaversion(sn.SchemaVersion).
		SetOvalversion(sn.Version).
		SetClass(sn.Class).
		SetFamily(sn.AffectedFamily).
		SetCopyright(sn.AdvisoryRights).
		SetTimestamp(CreatedAt.String()).
		SetID(sn.ID).
		SetTitle(sn.Title).
		SetDescription(sn.Description).
		SetSeverity(sn.AdvisorySeverity).
		SetIssuedate(sn.AdvisoryIssued).
		SetPlatform(sn.AffectedPlatform).
		SetArchList(sn.Archlist).
		SetCveList(sn.Reference).
		SetStateList(sn.State).
		SetObjectList(sn.Object).
		SetTestList(sn.Test).
		Save(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to write oval: %v", err)
	}
	return oval, nil
}

func GetOvalID(ovalid string, client *ent.Client) string {
	oval, _ := client.Oval.Query().Where(oval.IDEQ(ovalid)).First(context.Background())
	if oval == nil {
		return ""
	} else {
		return oval.ID
	}
}

func GenerateID(dbname string, value string, client *ent.Client) (string, error) {
	if dbname == "object" {
		object, err := client.Object.Query().Where(object.NameEQ(value)).First(context.Background())
		if object == nil {
			num, _ := client.Object.Query().Count(context.Background())
			//common obj number start with "3", openscap required non Zero start
			newID := "oval:cn.ctyun.ctyunos:obj:" + fmt.Sprintf("3%011d", num)
			obj, _ := client.Object.Create().SetObjectID(newID).SetName(value).Save(context.Background())
			return obj.ObjectID, err
		} else {
			return object.ObjectID, err
		}
	} else if dbname == "state" {
		state, err := client.State.Query().Where(state.ValueEQ(value)).First(context.Background())
		if state == nil {
			num, _ := client.State.Query().Count(context.Background())
			//common ste number start with "3", openscap required non Zero start
			newID := "oval:cn.ctyun.ctyunos:ste:" + fmt.Sprintf("3%011d", num)
			state, _ := client.State.Create().SetStateID(newID).SetValue(value).SetTag("evr").SetOperation("less than").SetDatatype("evr_string").Save(context.Background())
			return state.StateID, err
		} else {
			return state.StateID, err
		}
	} else if dbname == "test" {
		test, err := client.Test.Query().Where(test.CommentEQ(value)).First(context.Background())
		if test == nil {
			num, _ := client.Test.Query().Count(context.Background())
			//common tst number start with "3", openscap required non Zero start
			newID := "oval:cn.ctyun.ctyunos:tst:" + fmt.Sprintf("3%011d", num)
			items := strings.Split(value, " ")
			obj, _ := client.Object.Query().Where(object.NameEQ(items[0])).First(context.Background())
			state, _ := client.State.Query().Where(state.ValueEQ(items[len(items)-1])).First(context.Background())
			test, err := client.Test.Create().SetComment(value).SetTestID(newID).SetObjectID(obj.ObjectID).SetStateID(state.StateID).Save(context.Background())
			return test.TestID, err
		} else {
			return test.TestID, err
		}
	} else if dbname == "cveref" {
		reference, err := client.Cveref.Query().Where(cveref.RefIDEQ(value)).First(context.Background())
		if reference == nil {
			RefUrl := common.CveRef + value
			newcve, err := client.Cveref.Create().SetRefID(value).SetRefURL(RefUrl).Save(context.Background())
			if err != nil {
				return "", fmt.Errorf("failed to create new cve reference: %s, error is: %v", value, err)
			}
			return newcve.RefID, err
		} else {
			return reference.RefID, err
		}
	} else {
		return "", fmt.Errorf("GenerateID failed, unknown dbname: %s", dbname)
	}
}

func WriteReference(snrlist []SecurityNoticeReference, client *ent.Client) error {
	for _, snr := range snrlist {
		RefID, err := GenerateID("cveref", snr.RefId, client)
		if RefID == "" {
			return fmt.Errorf("failed to write cveref with error: %v", err)
		}
		log.Debug("Using RefID record:", RefID)
	}
	return nil
}

func WriteTest(comment string, client *ent.Client) (string, error) {
	Testid, err := GenerateID("test", comment, client)
	if Testid == "" {
		return "", fmt.Errorf("failed to write test with error: %v", err)
	}
	log.Debug("Using TestID record:", Testid)
	return Testid, nil
}

func WriteObject(filename string, client *ent.Client) error {
	ObjectID, err := GenerateID("object", filename, client)
	if ObjectID == "" {
		return fmt.Errorf("failed to write object with error: %v", err)
	}
	log.Debug("Using ObjectID record:", ObjectID)
	return nil
}

func WriteState(version string, client *ent.Client) error {
	StateID, err := GenerateID("state", version, client)
	if StateID == "" {
		return fmt.Errorf("failed to write state with error: %v", err)
	}
	log.Debug("Using StateID record:", StateID)
	return nil
}

// HandleSecurityNotice 处理安全通知，并存入数据库
// 参数 jsonSecNotice JsonSecurityNotice 类型，包含安全通知的 JSON 结构体
// 返回值 SecurityNotice 类型，表示处理后的安全通知信息结构体
// 返回值 error 类型，表示处理过程中可能出现的错误
func HandleSecurityNotice(jsonSecNotice JsonSecurityNotice) (string, error) {
	// 连接数据库
	if jsonSecNotice.SecurityNoticeNo == "" {
		return "", fmt.Errorf("input of HandleSecurityNotice is empty")
	}
	db, err := common.ConnectDB()
	if err != nil {
		return "", fmt.Errorf("failed to connect database: %v", err)
	}
	defer db.Close()

	//如果Test表是新建的，则初始化入系统安装（2级），架构判断（1级）的测试。未来package的检测均为3级
	num, _ := db.Test.Query().Count(context.Background())
	if num == 0 {
		log.Debug("Initializing tests table...")
		for id, product := range strings.Split(common.Productlist, " ") {
			db.Test.Create().SetComment("CTyunOS " + product + " is installed").SetTestID(fmt.Sprintf("oval:cn.ctyun.ctyunos:tst:20000000000%d", id+1)).SetObjectID("oval:cn.ctyun.ctyunos:obj:100000000001").SetStateID(fmt.Sprintf("oval:cn.ctyun.ctyunos:ste:20000000000%d", id+1)).Save(context.Background())
		}
		for id, arch := range strings.Split(common.Archlist, " ") {
			db.Test.Create().SetComment(fmt.Sprintf("CTyunOS Linux arch is %s", arch)).SetTestID(fmt.Sprintf("oval:cn.ctyun.ctyunos:tst:10000000000%d", id+1)).SetObjectID("oval:cn.ctyun.ctyunos:obj:100000000001").SetStateID(fmt.Sprintf("oval:cn.ctyun.ctyunos:ste:10000000000%d", id+1)).Save(context.Background())
		}
	}
	//如果Object表是新建的，则初始化入ctyunos-release, 它被产品安装及架构安装检测所共用
	num, _ = db.Object.Query().Count(context.Background())
	if num == 0 {
		log.Debug("Initializing objects table...")
		db.Object.Create().SetName("ctyunos-release").SetObjectID("oval:cn.ctyun.ctyunos:obj:100000000001").Save(context.Background())
	}
	//如果State表是新建的，则初始化入系统安装状态值为product，架构判断状态值arch
	num, _ = db.State.Query().Count(context.Background())
	if num == 0 {
		log.Debug("Initializing state table...")
		for id, product := range strings.Split(common.Productlist, " ") {
			db.State.Create().SetStateID(fmt.Sprintf("oval:cn.ctyun.ctyunos:ste:20000000000%d", id+1)).SetDatatype("string").SetOperation("pattern match").SetTag("version").SetValue(product).Save(context.Background())
		}
		for id, arch := range strings.Split(common.Archlist, " ") {
			db.State.Create().SetStateID(fmt.Sprintf("oval:cn.ctyun.ctyunos:ste:10000000000%d", id+1)).SetDatatype("string").SetOperation("pattern match").SetTag("arch").SetValue(arch).Save(context.Background())
		}
	}

	// 初始化 SecurityNotice 结构体，先查在db中是否已经存在，若不存在，将SecurityNotice内数据写入数据表oval
	ovalid := common.CTyunOSDefinitionStr + strings.ReplaceAll(jsonSecNotice.AnnouncementTime, "-", "")
	ret := GetOvalID(ovalid, db)
	if ret == "" {
		// 初始化安全通知引用信息，并添加到 Reference 中，安全公告页面（CTyunOS-SA）有且仅有一条，特殊地放在第一位
		var References []SecurityNoticeReference
		SaRef := SecurityNoticeReference{
			Source: "CTyunOS-SA",
			RefId:  jsonSecNotice.SecurityNoticeNo,
			RefUrl: jsonSecNotice.NoticeURL,
		}
		References = append(References, SaRef)

		// 遍历 CVE 列表，添加 CVE 信息到 securityNoticeReferences， 排在2至n位
		cve_list := ""
		for _, cve := range jsonSecNotice.CVEList {
			cve_list += cve.CveID + " "
			referenceCve := SecurityNoticeReference{
				Source: "CVE",
				RefId:  cve.CveID,
				RefUrl: cve.URL,
			}
			References = append(References, referenceCve)
		}

		// 将References内数据写入数据表reference
		err = WriteReference(References, db)
		if err != nil {
			fmt.Println("failed to write reference records:", err)
			return "", err
		}

		//分解Files中的数据，写入数据库
		object_list := ""
		state_list := ""
		test_list := ""
		for _, file := range jsonSecNotice.Files[0].List {
			// fmt.Println(file.FileName)
			// fmt.Println(file.Version)
			// fmt.Println(file.FileURL)
			var version = file.Version
			if file.Version == "" {
				str := strings.Split(file.FileURL, "/")
				myRegexp := regexp.MustCompile("-[0-9].[0-9.A-z]*-[0-9.A-z]+.ctl[0-9]")
				params := myRegexp.FindStringSubmatch(str[len(str)-1])
				if params == nil {
					log.Error(str[len(str)-1] + " is not valid regex package name\n")
				}
				version = "0:" + params[0][1:]
			}
			object_list += file.FileName + " "
			state_list += version + " "
			err = WriteObject(file.FileName, db)
			if err != nil {
				return "", err
			}
			err = WriteState(version, db)
			if err != nil {
				return "", err
			}
			testid, err := WriteTest(file.FileName+" is earlier than "+version, db)
			test_list += testid + " "
			if err != nil {
				return "", err
			}
		}

		// 枚举Type为Severity
		var severity = ""
		switch jsonSecNotice.Type {
		case 1:
			severity = "low"
		case 2:
			severity = "medium"
		case 3:
			severity = "high"
		case 4:
			severity = "critical"
		default:
			severity = "unknown"
		}
		var securityNotice = SecurityNotice{
			ID:               ovalid,
			ProductName:      common.ProductName,
			ProductVersion:   common.ProductVersion,
			SchemaVersion:    common.SchemaVersion,
			Version:          common.OvalVersion,
			Class:            common.Class,
			Title:            jsonSecNotice.SecurityNoticeNo + " " + jsonSecNotice.Summary,
			Description:      jsonSecNotice.Description,
			AffectedFamily:   common.Family,
			AffectedPlatform: jsonSecNotice.AffectedProduct,
			AdvisorySeverity: severity,
			AdvisoryRights:   common.CopyRights,
			AdvisoryIssued:   jsonSecNotice.AnnouncementTime,
			Archlist:         common.Archlist,
			Reference:        strings.TrimRight(cve_list, " "),
			Object:           strings.TrimRight(object_list, " "),
			State:            strings.TrimRight(state_list, " "),
			Test:             strings.TrimRight(test_list, " "),
		}
		_, err = WriteOval(securityNotice, db)
		if err != nil {
			fmt.Println("failed to write oval records:", err)
			return "", err
		}
		return securityNotice.ID, nil
	}
	return ret, nil
}

// ParseSecNoticeFromJson 从指定的JSON文件中解析安全通知
// 参数:
// - filePath: 指向要解析的JSON文件的路径
// 返回值:
// - error: 如果解析过程中遇到错误，则返回error；否则返回nil
func ParseSecNoticeFromJson(filePath string) error {
	// 解析json文件，放入JsonSecurityNotice结构体中
	jsonSecurityNotice, err := parseJSONFile(filePath)
	if err != nil {
		log.Debug(jsonSecurityNotice)
		return err // 如果解析文件时出错，则打印错误信息并返回错误
	}

	// 将JsonSecurityNotice结构体数据写入ovals cverefs objects states tests数据表
	ovalid, err := HandleSecurityNotice(jsonSecurityNotice)
	if err != nil {
		return err // 如果处理数据时出错，则打印错误信息并返回错误
	}
	log.Info(ovalid, " file is prceeded")
	return nil // 如果没有错误，则返回nil
}

// ParseSecNoticesFormJsonDir 从指定目录中解析所有JSON格式的安全通知
// 参数:
// dirPath string - 指定的目录路径
// 返回值:
// error - 如果处理过程中遇到错误，将返回error；否则返回nil
func ParseSecNoticesFormJsonDir(dirPath string) error {
	// 检查目录是否存在
	if strings.HasPrefix(dirPath, "/") || strings.Contains(dirPath, ":") {
		log.Debug("Using absolute dirpath: ", dirPath)
	} else {
		cwd, _ := os.Getwd()
		dirPath = cwd + "/" + dirPath
	}
	_, err := os.Stat(dirPath)
	if err != nil {
		log.Fatal("dir ", dirPath, " does not exist.")
		return err
	}

	// 读取目录中的所有文件和子目录
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	// 遍历读取到的文件和子目录
	for _, file := range files {
		// 如果是文件，则尝试解析安全通知
		if !file.IsDir() {
			var _ = ParseSecNoticeFromJson(dirPath + "/" + file.Name())
		} else {
			// 如果不是目录，则打印错误提示信息
			log.Error(file.Name(), " is not a dir")
		}
	}
	return nil
}

func Urlget(baseUrl string, structParam interface{}) []byte {
	// 创建查询参数
	queryParams := url.Values{}
	v := reflect.ValueOf(structParam)
	t := v.Type()

	// 遍历结构体字段，将字段名和值添加到查询参数
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// 使用 struct 标签中的 "query" 值作为查询参数的键名
		queryKey := field.Tag.Get("query")
		if queryKey == "" {
			// 如果没有指定查询参数的键名，则使用字段名
			queryKey = field.Name
		}

		// 将字段值转换为字符串并添加到查询参数
		queryValue := fmt.Sprintf("%v", value.Interface())
		queryParams.Add(queryKey, queryValue)
	}

	// 构建带查询参数的 URL
	urlWithParams := baseUrl + "?" + queryParams.Encode()
	req, err := http.NewRequest("GET", urlWithParams, nil)
	if err != nil {
		log.Fatal("Build HTTP Get request failed with Error: ", err)
		return nil
	}

	// 创建 HTTP 客户端并发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("HTTP Get request failed with Error: ", err)
		return nil
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("HTTP GET error: %v\n", err)
		return nil
	}

	// 检查响应状态码
	if resp.StatusCode == http.StatusOK {
		log.Debug("Request successful:", string(body))
		return body
	} else {
		log.Error("Request failed with status: ", resp.StatusCode)
		return nil
	}
}

func Urlpost(baseUrl string, structParam interface{}) []byte {
	// 将结构体参数编码为 JSON 数据
	jsonData, err := json.Marshal(structParam)
	if err != nil {
		log.Fatal("Marshal to Json failed with Error: ", err)
		return nil
	}
	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", baseUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("Create HTTP request failed with Error: ", err)
		return nil
	}

	// 设置请求头，指定 JSON 内容类型
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	log.Debug("HTTP Request is: ", req)

	// 创建 HTTP 客户端并发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Connection to ", baseUrl, " failed with Error: ", err)
		return nil
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("HTTP POST error: %v\n", err)
		return nil
	}

	// 检查响应状态码
	if resp.StatusCode == http.StatusOK {
		var bodystrim string
		if len(body) > 500 {
			bodystrim = string(body)[:500] + "..."
		} else {
			bodystrim = string(body)
		}
		log.Debug("Response from ", baseUrl, " First 500 bytes are:", bodystrim)
		return body
	} else {
		log.Error("Request failed with status: %d\n", resp.StatusCode)
		return nil
	}
}

func ParseRestfulUrl() error {
	type Urlparams struct {
		Type             int    `json:"type,omitempty"`
		From             string `json:"start_time,omitempty"`
		To               string `json:"end_time,omitempty"`
		Product          string `json:"product,omitempty"`
		Keyword          string `json:"key_word,omitempty"`
		SecurityNoticeNo string `json:"security_notice_no,omitempty"`
		Pagesize         int    `json:"page_size,omitempty"`
	}
	datefrom := viper.GetString(flag.KeyDateFrom)
	dateto := viper.GetString(flag.KeyDateTo)
	product := viper.GetString(flag.KeyProduct)
	keyword := viper.GetString(flag.KeyKeyword)
	stype := viper.GetInt(flag.KeyType)
	params := Urlparams{From: datefrom}
	params.Pagesize = 99999
	if dateto != "" && dateto != "now" {
		params.To = dateto
	}
	if product != "" {
		params.Product = product
	} else {
		params.Product = "ctyunos-2.0.1"
	}
	if keyword != "" {
		params.Keyword = keyword
	}
	if stype != 0 {
		params.Type = stype
	}

	// 调用通用 POST 请求函数, 获取json摘要列表, 解析出json list
	log.Debug("params: ", fmt.Sprintf("%+v", params))
	body := Urlpost(common.CvelistAPI+"list", params)
	var cvesummary CveSummary
	err := json.Unmarshal(body, &cvesummary)
	if err != nil {
		return fmt.Errorf("fail to parse CveSummary to json: %v", err)
	}

	// 遍历 CveSummary.Data.List
	amount := 0
	for _, content := range cvesummary.Data.List {
		// Get cve detail from API
		params = Urlparams{SecurityNoticeNo: content.SecurityNoticeNo}
		body = Urlpost(common.CvelistAPI+"detail", params)

		// 将API返回的body内容(json格式的)解析为jsonSecurityNotice结构体. 必须要将body转换成[]byte类型，否则json.Unmarshal会报错
		var httpresponse HttpResponse
		err := json.Unmarshal([]byte(body), &httpresponse)
		if err != nil {
			return fmt.Errorf("fail to parse body to httpresponse: %v", err)
		}
		jsonSecurityNotice := httpresponse.Data
		// 如果没解析出CVE号，则打印错误信息并返回错误
		if jsonSecurityNotice.SecurityNoticeNo == "" {
			//printJsonSecurityNotice(jsonSecurityNotice)
			log.Error("Parse CVE detail content failed: ", content.SecurityNoticeNo)
			continue
		}

		// 将JsonSecurityNotice结构体数据写入ovals cverefs objects states tests数据表
		ovalid, err := HandleSecurityNotice(jsonSecurityNotice)
		if err != nil {
			return err // 如果处理数据时出错，则打印错误信息并返回错误
		}
		log.Debug(ovalid, " detail is prceeded")
		fmt.Printf(".")
		amount += 1
	}
	fmt.Printf("\n")
	log.Info(amount, " CVEs are prceeded successfully")
	return nil
}
