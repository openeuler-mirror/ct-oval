package securitynotice

import (
	"bytes"
	"context"
	"ct_oval_tool/cmd/flag"
	"ct_oval_tool/pkg/ent/oval"
	"ct_oval_tool/pkg/ovalxml/common"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/spf13/viper"
)

func TestParseJSONData(t *testing.T) {
	data, err := os.ReadFile("../../example/security_notice1.json")
	if err != nil {
		pwd, _ := os.Getwd()
		fmt.Printf("无法读取文件: %v/../../example/security_notice1.json", pwd)
	}
	testCases := []struct {
		input    []byte
		expected JsonSecurityNotice
		err      error
	}{
		{
			input: []byte(data),
			expected: JsonSecurityNotice{
				ID:               3371,
				SecurityNoticeNo: "CTyunOS-SA-2021-1007",
				NoticeURL:        "https://ctyunos.ctyun.cn/#/support/safetyDetail?id=CTyunOS-SA-2021-1007",
			},
			err: nil,
		},
	}

	for _, tc := range testCases {
		result, err := parseJSONData(tc.input)

		if err != nil && tc.err == nil {
			t.Errorf("parseJSONData(%s) returned unexpected error: %v", []byte(data), err)
		}

		if err == nil && tc.err != nil {
			t.Errorf("parseJSONData(%s) did not return expected error: %v", []byte(data), tc.err)
		}

		if err != nil && tc.err != nil && err.Error() != tc.err.Error() {
			t.Errorf("parseJSONData(%s) returned unexpected error: %v, expected: %v", []byte(data), err, tc.err)
		}
		assert.Equal(t, tc.expected.ID, result.ID)
		assert.Equal(t, tc.expected.SecurityNoticeNo, result.SecurityNoticeNo)
		assert.Equal(t, tc.expected.NoticeURL, result.NoticeURL)
		assert.Equal(t, 325, len(result.Subject))
		typecvelist := fmt.Sprintf("%+v", reflect.TypeOf(result.CVEList))
		assert.Equal(t, "[]securitynotice.CVE", typecvelist)
		typefiles := fmt.Sprintf("%+v", reflect.TypeOf(result.Files))
		assert.Equal(t, "[]securitynotice.File", typefiles)
	}
}

func TestParseJSONFile(t *testing.T) {
	pwd, _ := os.Getwd()
	filePath := pwd + "/../../example/security_notice1.json"

	notice, err := parseJSONFile(filePath)
	if err != nil {
		t.Errorf("parseJSONFile() returned an error: %v", err)
	}

	// Add test cases here to validate the correctness of the parsed data
	// e.g. compare the fields of notice with expected values
	assert.Equal(t, "CTyunOS-SA-2021-1007", notice.SecurityNoticeNo)
	assert.Equal(t, 325, len(notice.Subject))
	typecvelist := fmt.Sprintf("%+v", reflect.TypeOf(notice.CVEList))
	assert.Equal(t, "[]securitynotice.CVE", typecvelist)
	typefiles := fmt.Sprintf("%+v", reflect.TypeOf(notice.Files))
	assert.Equal(t, "[]securitynotice.File", typefiles)
}

func TestPrintJsonSecurityNotice(t *testing.T) {
	securityNotice := JsonSecurityNotice{
		ID:                12345,
		SecurityNoticeNo:  "SN-001",
		Subject:           "Security Notice",
		NoticeURL:         "https://example.com/notice",
		Summary:           "This is a summary of the security notice",
		Type:              4,
		AffectedProduct:   "Product X",
		AffectedComponent: "Component Y",
		AnnouncementTime:  "2022-01-01",
		Description:       "This is a detailed description of the security notice",
		Introduction:      "This is an introduction to the security notice",
		CVEList: []CVE{
			{
				URL:   "https://example.com/cve-1",
				CveID: "CVE-2022-001",
			},
			{
				URL:   "https://example.com/cve-2",
				CveID: "CVE-2022-002",
			},
		},
		Files: []File{
			{
				Arch: "amd64",
				List: []RpmFile{
					{
						FileName: "file1.txt",
						Version:  "v1.0.0",
						FileURL:  "https://example.com/file1.txt",
					},
					{
						FileName: "file2.txt",
						Version:  "v1.0.1",
						FileURL:  "https://example.com/file2.txt",
					},
				},
			},
			{
				Arch: "arm64",
				List: []RpmFile{
					{
						FileName: "file3.txt",
						Version:  "v1.0.0",
						FileURL:  "https://example.com/file3.txt",
					},
				},
			},
		},
	}

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printJsonSecurityNotice(securityNotice)
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	// Compare the actual output with the expected output
	assert.Equal(t, len(string(out)), 833)
}

func TestWriteOval(t *testing.T) {
	// Create a mock client
	db, err := common.ConnectDB()
	if err != nil {
		fmt.Printf("failed to connect database: %v", err)
	}
	defer db.Close()

	// Create a test security notice. Mock a record oval:cn.ctyun.ctyunos:def:202102081
	sn := SecurityNotice{
		ID:               "oval:cn.ctyun.ctyunos:def:202102081",
		ProductName:      common.ProductName,
		ProductVersion:   common.ProductVersion,
		SchemaVersion:    common.SchemaVersion,
		Version:          common.OvalVersion,
		Class:            common.Class,
		Title:            "CTyunOS-SA-2021-1011 golang security update",
		Description:      "The Go Programming Language",
		AffectedFamily:   common.Family,
		AffectedPlatform: "ctyunos-2.0.1",
		AdvisorySeverity: "medium",
		AdvisoryRights:   common.CopyRights,
		AdvisoryIssued:   "2021-02-08",
		Archlist:         common.Archlist,
		Reference:        "CVE-2020-29509",
		Object:           "golang",
		State:            "1.15.7-33.ctl2",
		Test:             "oval:cn.ctyun.ctyunos:tst:300000000009",
	}

	// Call the function to test
	ovalout, err := WriteOval(sn, db)

	// Check if the function returned an error
	assert.Equal(t, err, nil)

	// Add more assertions for the oval fields if needed
	assert.Equal(t, sn.ProductName, ovalout.Productname, "Oval productname is incorrect")
	assert.Equal(t, sn.ProductVersion, ovalout.Productversion, "Oval productversion is incorrect")
	// Delete mocked record
	db.Oval.Delete().Where(oval.IDEQ("oval:cn.ctyun.ctyunos:def:202102081")).Exec(context.Background())
}

func TestGetOvalID(t *testing.T) {
	// Create a test client
	db, err := common.ConnectDB()
	if err != nil {
		fmt.Printf("failed to connect database: %v", err)
	}
	defer db.Close()

	// Test case 1: Valid ovalid
	ovalid := "oval:cn.ctyun.ctyunos:def:20210208"
	expectedID := "oval:cn.ctyun.ctyunos:def:20210208"
	actualID := GetOvalID(ovalid, db)
	assert.Equal(t, expectedID, actualID, "GetOvalID should return an ID (string) for valid ovalid")

	// Test case 2: Invalid ovalid
	invalidOvalid := "invalid_id"
	expectedID = ""
	actualID = GetOvalID(invalidOvalid, db)
	assert.Equal(t, expectedID, actualID, "GetOvalID should return an empty string for invalid ovalid")
}

func TestGenerateID(t *testing.T) {
	db, err := common.ConnectDB()
	if err != nil {
		fmt.Printf("failed to connect database: %v", err)
	}
	defer db.Close()

	t.Run("TestGenerateID_Object", func(t *testing.T) {
		dbname := "object"
		value := "golang"
		expectedID := "oval:cn.ctyun.ctyunos:obj:300000000007"

		// Call the function
		actualID, err := GenerateID(dbname, value, db)

		// Verify the result
		assert.Equal(t, err, nil)
		assert.Equal(t, expectedID, actualID)
	})

	t.Run("TestGenerateID_State", func(t *testing.T) {
		dbname := "state"
		value := "2.0.1"
		expectedID := "oval:cn.ctyun.ctyunos:ste:200000000001"

		// Call the function
		actualID, err := GenerateID(dbname, value, db)

		// Verify the result
		assert.Equal(t, err, nil)
		assert.Equal(t, expectedID, actualID)
	})

	t.Run("TestGenerateID_Test", func(t *testing.T) {
		dbname := "test"
		value := "CTyunOS 2.0.1 is installed"
		expectedID := "oval:cn.ctyun.ctyunos:tst:200000000001"
		// Call the function
		actualID, err := GenerateID(dbname, value, db)

		// Verify the result
		assert.Equal(t, err, nil)
		assert.Equal(t, expectedID, actualID)
	})

	// t.Run("TestGenerateID_Test", func(t *testing.T) {
	// 	dbname := "test"
	// 	value := "CTyunOS 23.01 Linux is installed"
	// 	expectedID := "oval:cn.ctyun.ctyunos:tst:200000000002"
	// 	// Call the function
	// 	actualID, err := GenerateID(dbname, value, db)

	// 	// Verify the result
	// 	assert.Equal(t, err, nil)
	// 	assert.Equal(t, expectedID, actualID)
	// })

	t.Run("TestGenerateID_Cveref", func(t *testing.T) {
		dbname := "cveref"
		value := "CVE-2020-27762"
		expectedID := "CVE-2020-27762"
		// Call the function
		actualID, err := GenerateID(dbname, value, db)

		// Verify the result
		assert.Equal(t, err, nil)
		assert.Equal(t, expectedID, actualID)
	})
}

func TestParseSecNoticeFromJson(t *testing.T) {
	// Test case 1: when parseJSONFile returns an error
	filePath := "invalid_file_path"
	expectedErr := errors.New("无法读取文件: invalid_file_path")

	err := ParseSecNoticeFromJson(filePath)

	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, but got: %v", expectedErr, err)
	}

	// Test case 2: when both parseJSONFile and HandleSecurityNotice succeed
	pwd, _ := os.Getwd()
	filePath = pwd + "/../../example/security_notice1.json"
	//expectedOvalid := "valid_ovalid"

	err = ParseSecNoticeFromJson(filePath)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	// Assert the log output if needed
	// if logOutput != expectedLogOutput {
	// 	t.Errorf("Expected log output: %v, but got: %v", expectedLogOutput, logOutput)
	// }
}

func TestParseSecNoticesFormJsonDir(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "test_dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试文件
	testFile := filepath.Join(tempDir, "test.json")
	err = os.WriteFile(testFile, []byte("{}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 调用函数进行测试
	err = ParseSecNoticesFormJsonDir(tempDir)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUrlget(t *testing.T) {
	baseUrl := "http://example.com"
	type TestStruct struct {
		Field1 string `query:"field1"`
		Field2 int    `query:"field2"`
	}

	structParam := TestStruct{
		Field1: "value1",
		Field2: 123,
	}

	expectedUrl := "http://example.com?field1=value1&field2=123"
	expectedBody := []byte("expected body")

	// Mock http.Client
	mockClient := &http.Client{
		Transport: &MockTransport{
			ExpectedURL:    expectedUrl,
			ExpectedMethod: "GET",
			ResponseBody:   expectedBody,
			Err:            nil,
		},
	}

	// Set the mock client
	oldClient := http.DefaultClient
	http.DefaultClient = mockClient

	// Call the function
	result := Urlget(baseUrl, structParam)

	// Check the result
	if len(result) != 1256 {
		t.Errorf("Expected body length: 1256, but got: %d", len(result))
	}

	// Restore the default client
	http.DefaultClient = oldClient
}

type MockTransport struct {
	ExpectedURL    string
	ExpectedMethod string
	ResponseBody   []byte
	Err            error
}

func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != t.ExpectedURL {
		return nil, fmt.Errorf("Expected URL: %s, but got: %s", t.ExpectedURL, req.URL.String())
	}

	if req.Method != t.ExpectedMethod {
		return nil, fmt.Errorf("Expected Method: %s, but got: %s", t.ExpectedMethod, req.Method)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewReader(t.ResponseBody)),
	}, t.Err
}

func TestUrlpost(t *testing.T) {
	baseUrl := common.CvelistAPI + "list"
	structParam := struct {
		Type             int    `json:"type,omitempty"`
		From             string `json:"start_time,omitempty"`
		To               string `json:"end_time,omitempty"`
		Product          string `json:"product,omitempty"`
		Keyword          string `json:"key_word,omitempty"`
		SecurityNoticeNo string `json:"security_notice_no,omitempty"`
	}{
		Type:    4,
		From:    "2023-01-01",
		To:      "2023-02-01",
		Product: "ctyunos-2.0.1",
		Keyword: "git",
	}

	expectedResponse := []byte(`{"code":0,"data":{"count":2,"list":[{"id":2569,"security_notice_no":"CTyunOS-SA-2023-21361","summary":"git security update","type":4,"affected_product":"ctyunos-2.0.1","affected_component":"git","announcement_time":"2023-02-01"},{"id":2568,"security_notice_no":"CTyunOS-SA-2023-1044","summary":"git security update","type":4,"affected_product":"ctyunos-2.0.1","affected_component":"git","announcement_time":"2023-02-02"}]},"msg":"获取成功"}`)

	// Mock HTTP Server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected request method %s, got %s", http.MethodPost, r.Method)
		}

		// Check request URL
		if r.URL.String() != baseUrl {
			t.Errorf("Expected request URL %s, got %s", baseUrl, r.URL.String())
		}

		// Check request header content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected request header Content-Type %s, got %s", "application/json", r.Header.Get("Content-Type"))
		}

		// Check request header user agent
		if r.Header.Get("User-Agent") != "Mozilla/5.0" {
			t.Errorf("Expected request header User-Agent %s, got %s", "Mozilla/5.0", r.Header.Get("User-Agent"))
		}

		// Read request body
		var body struct {
			Type    int    `json:"type,omitempty"`
			Product string `json:"product,omitempty"`
			Keyword string `json:"key_word,omitempty"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}

		// Check request body
		if body.Product != structParam.Product || body.Keyword != structParam.Keyword || body.Type != structParam.Type {
			t.Errorf("Expected request body %+v, got %+v", structParam, body)
		}

		// Respond with mock response
		w.WriteHeader(http.StatusOK)
		w.Write(expectedResponse)
	})

	// Make test request
	response := Urlpost(baseUrl, structParam)

	// Check response
	if response == nil {
		t.Error("Expected non-nil response, got nil")
	}

	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Expected response %s, got %s", expectedResponse, response)
	}
}

func TestParseRestfulUrl(t *testing.T) {
	// 初始化测试数据
	viper.Set(flag.KeyDateFrom, "2023-02-01")
	viper.Set(flag.KeyDateTo, "2023-03-31")
	viper.Set(flag.KeyProduct, "ctyunos-2.0.1")
	viper.Set(flag.KeyKeyword, "")
	viper.Set(flag.KeyType, 1)

	// 执行函数
	err := ParseRestfulUrl()

	// 断言结果
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
	}
}
