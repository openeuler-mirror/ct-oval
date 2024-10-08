package securitynotice

// 自定义类型
type OvalDataType int

// 声明每个枚举项的索引值
const (
	Platform OvalDataType = iota + 1 // Index = 1
	Arch                             // Index = 2
	Package                          // Index = 3
)

type SecurityNoticeReference struct {
	Source string
	RefUrl string
	RefId  string
}

type SecurityNoticeObject struct {
	ObjectId string
	Name     string
}

type SecurityNoticeTest struct {
	TestId  string
	Comment string
}

type SecurityNoticeState struct {
	StateId string
	Value   string
}

type SecurityNotice struct {
	ID               string
	ProductName      string
	ProductVersion   string
	SchemaVersion    string
	Version          string
	Class            string
	Title            string
	Description      string
	AffectedFamily   string
	AffectedPlatform string
	AdvisorySeverity string
	AdvisoryRights   string
	AdvisoryIssued   string
	Archlist         string
	Reference        string //安全公告链接+cve_list
	Test             string //test_list
	Object           string //object_list
	State            string //state_list
}
