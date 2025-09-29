package securitynotice

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// --- 1. Unified Data Structures (Unchanged) ---
// These structs represent the generic, OS-agnostic format that all parsers will produce.

type UnifiedAdvisory struct {
	ID          string
	Title       string
	Description string
	Severity    string
	IssuedDate  string // <-- ADDED: The release date of the advisory.
	References  []string
	CVEs        []string
	Products    []AffectedProduct
}

type AffectedProduct struct {
	Name     string
	Packages []PackageInfo
}

type PackageInfo struct {
	Name         string
	Architecture string
	FixedVersion string
}

// --- 2. 接口定义 ---
type AdvisoryParser interface {
	Parse(content []byte) (*UnifiedAdvisory, error)
}

type AdvisoryFileParser interface {
	ParseFile(filePath string) (*UnifiedAdvisory, error) // 解析文件
}

// --- 3. CSAFParser 实现 AdvisoryParser 接口 ---
type CSAFParser struct{}

var _ AdvisoryParser = (*CSAFParser)(nil)

func (p *CSAFParser) Parse(content []byte) (*UnifiedAdvisory, error) {
	var csafDoc CSAFDoc
	if err := json.Unmarshal(content, &csafDoc); err != nil {
		return nil, err
	}
	return p.transform(csafDoc)
}

// 再实现 ParseFile 方法，负责读取文件并调用 Parse 解析字节流
func (p *CSAFParser) ParseFile(filePath string) (*UnifiedAdvisory, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	// 调用自身的 Parse 方法（接收字节流）
	return p.Parse(content)
}

// --- 4. FileParser 实现 AdvisoryFileParser 接口 ---
type FileParser struct {
	parser AdvisoryParser // 依赖注入的解析器
}

// NewFileParser 创建FileParser实例，传入AdvisoryParser
func NewFileParser(parser AdvisoryParser) *FileParser {
	return &FileParser{parser: parser}
}

func (p *CSAFParser) transform(doc CSAFDoc) (*UnifiedAdvisory, error) {
	v := firstVuln(doc)
	if v == nil || strings.TrimSpace(v.CVE) == "" {
		return nil, fmt.Errorf("CSAF document contains no valid vulnerability entry")
	}

	// 构建基础UnifiedAdvisory结构
	unified := &UnifiedAdvisory{
		ID:          doc.Document.Tracking.ID,
		Title:       doc.Document.Title,
		Description: firstDescription(v),
		Severity:    bucketSeverityFromScores(v),
		IssuedDate:  pickIssuedDate(doc),
		CVEs:        []string{v.CVE},
	}

	// 提取参考链接
	if advURL := preferSelfOrAdvisoryURL(v); advURL != "" {
		unified.References = append(unified.References, advURL)
	}
	for _, ref := range v.References {
		if ref.URL != "" {
			unified.References = append(unified.References, ref.URL)
		}
	}

	// 1. 提取AffectedProduct.Name：来自"openEuler"产品分支的product_id
	var affectedProduct AffectedProduct
	// 根分支为vendor "openEuler"（product_tree.branches[0]）
	if len(doc.ProductTree.Branches) > 0 {
		vendorBranch := doc.ProductTree.Branches[0]
		// 遍历vendor下的分支，寻找product_name为"openEuler"的分支
		for _, pb := range vendorBranch.Branches {
			if pb.Category == "product_name" && pb.Name == "openEuler" {
				// 遍历该分支下的product_version分支，获取product_id
				for _, pv := range pb.Branches {
					if pv.Category == "product_version" && pv.Product.ProductID != "" {
						affectedProduct.Name = pv.Product.ProductID
						break
					}
				}
				break
			}
		}
	}

	// 2. 提取AffectedProduct.Packages：来自name="src"的架构分支
	var packages []PackageInfo
	if len(doc.ProductTree.Branches) > 0 {
		vendorBranch := doc.ProductTree.Branches[0]
		// 遍历vendor下的架构分支，寻找name="src"的分支
		for _, archBranch := range vendorBranch.Branches {
			if archBranch.Name == "src" {
				// 遍历src分支下的所有产品版本, 不仅是archBranch.Category == "product_name"
				for _, prodVer := range archBranch.Branches {
					if prodVer.Category == "product_version" && prodVer.Product.Name != "" {
						pkgName := prodVer.Product.Name
						// 解析包名（如"dpdk-21.11-81.oe2203sp3.src.rpm"）
						// 去除.rpm后缀
						withoutRpm := strings.TrimSuffix(pkgName, ".src.rpm")
						if withoutRpm == pkgName {
							// 不是rpm包，跳过
							continue
						}
						// 按最后一个"."分割，获取架构（src）
						lastDotIdx := strings.LastIndex(withoutRpm, ".")
						if lastDotIdx == -1 {
							continue
						}
						architecture := withoutRpm[lastDotIdx+1:]
						baseName := withoutRpm[:lastDotIdx]

						// 分割包名和版本（第一个"-"之后为版本）
						firstDashIdx := strings.Index(baseName, "-")
						if firstDashIdx == -1 {
							continue
						}
						pkg := baseName[:firstDashIdx]
						fixedVersion := baseName[firstDashIdx+1:]

						packages = append(packages, PackageInfo{
							Name:         pkg,
							Architecture: architecture,
							FixedVersion: fixedVersion,
						})
					}
				}
				break // 只处理第一个src分支
			}
		}
	}
	affectedProduct.Packages = packages
	log.Debug("affectedProduct.Packages is:", affectedProduct.Packages)

	// 添加到最终产品列表
	unified.Products = []AffectedProduct{affectedProduct}

	return unified, nil
}

// --- Your CSAFDoc Struct and Helper Functions ---
// I've integrated your new struct and all helper functions directly.
// They are now used internally by the CSAFParser.

// CSAFDoc is a more detailed struct for parsing CSAF v2.0 JSON files.
type Document struct {
	AggregateSeverity AggregateSeverity `json:"aggregate_severity"`
	Category          string            `json:"category"`
	CsafVersion       string            `json:"csaf_version"`
	Distribution      Distribution      `json:"distribution"`
	Lang              string            `json:"lang"`
	Notes             []Note            `json:"notes"`
	Publisher         Publisher         `json:"publisher"`
	References        []Reference       `json:"references"`
	Title             string            `json:"title"`
	Tracking          Tracking          `json:"tracking"`
}

type AggregateSeverity struct {
	Namespace string `json:"namespace"`
	Text      string `json:"text"`
}

type Distribution struct {
	TLP TLP `json:"tlp"`
}

type TLP struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type Note struct {
	Text     string `json:"text"`
	Category string `json:"category"`
	Title    string `json:"title"`
}

type Publisher struct {
	IssuingAuthority string `json:"issuing_authority"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	ContactDetails   string `json:"contact_details"`
	Category         string `json:"category"`
}

type Reference struct {
	Summary  string `json:"summary"`
	Category string `json:"category"`
	URL      string `json:"url"`
}

type Tracking struct {
	InitialReleaseDate string            `json:"initial_release_date"`
	RevisionHistory    []RevisionHistory `json:"revision_history"`
	Generator          TrackingGenerator `json:"generator"`
	CurrentReleaseDate string            `json:"current_release_date"`
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	Status             string            `json:"status"`
}

type RevisionHistory struct {
	Date    string `json:"date"`
	Summary string `json:"summary"`
	Number  string `json:"number"`
}

type TrackingGenerator struct {
	Date   string                  `json:"date"`
	Engine TrackingGeneratorEngine `json:"engine"`
}

type TrackingGeneratorEngine struct {
	Name string `json:"name"`
}

// 产品关系结构体（对应product_tree.relationships）
type Relationship struct {
	RelatesToProductReference string          `json:"relates_to_product_reference"`
	ProductReference          string          `json:"product_reference"`
	FullProductName           FullProductName `json:"full_product_name"`
	Category                  string          `json:"category"`
}

// 完整产品名结构体（对应relationship中的full_product_name）
type FullProductName struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

// 之前定义的结构体保持不变，补充上述定义后即可解决undefined错误
type CSAFDoc struct {
	Document        Document        `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type ProductTree struct {
	Branches      []Branch       `json:"branches"`      // 对应JSON中的product_tree.branches
	Relationships []Relationship `json:"relationships"` // 对应JSON中的product_tree.relationships
}

type Branch struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Branches []Branch `json:"branches,omitempty"`
	Product  *Product `json:"product,omitempty"`
}

type Product struct {
	ProductIdentificationHelper ProductIdentificationHelper `json:"product_identification_helper"`
	ProductID                   string                      `json:"product_id"`
	Name                        string                      `json:"name"`
}

type ProductIdentificationHelper struct {
	CPE string `json:"cpe"`
}

// Vulnerability is a sub-struct for CSAFDoc.
type Vulnerability struct {
	CVE   string `json:"cve"`
	Title string `json:"title"`
	Notes []struct {
		Category string `json:"category"`
		Text     string `json:"text"`
	} `json:"notes,omitempty"`
	Scores []struct {
		Products []string `json:"products,omitempty"`
		CvssV3   struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
			Version      string  `json:"version"`
		} `json:"cvss_v3"`
	} `json:"scores,omitempty"`
	ProductStatus struct {
		KnownAffected []string `json:"known_affected,omitempty"`
		Fixed         []string `json:"fixed,omitempty"`
	} `json:"product_status,omitempty"`
	Remediations []struct {
		Category   string   `json:"category"`
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
		URL        string   `json:"url,omitempty"`
	} `json:"remediations,omitempty"`
	References []struct {
		Category string `json:"category"`
		Summary  string `json:"summary"`
		URL      string `json:"url"`
	} `json:"references,omitempty"`
}

// firstVuln safely gets the first vulnerability from the doc.
func firstVuln(doc CSAFDoc) *Vulnerability {
	if len(doc.Vulnerabilities) == 0 {
		return nil
	}
	return &doc.Vulnerabilities[0]
}

// pickIssuedDate selects and formats the advisory release date.
func pickIssuedDate(doc CSAFDoc) string {
	d := doc.Document.Tracking.CurrentReleaseDate
	if d == "" {
		d = doc.Document.Tracking.InitialReleaseDate
	}
	// CSAF uses RFC3339; OVAL often uses YYYY-MM-DD
	if t, err := time.Parse(time.RFC3339, d); err == nil {
		return t.Format("2006-01-02")
	}
	// if already in YYYY-MM-DD, just return as-is
	if len(d) >= 10 {
		return d[:10]
	}
	return ""
}

// bucketSeverityFromScores determines severity from a CVSS base score.
func bucketSeverityFromScores(v *Vulnerability) string {
	for _, s := range v.Scores {
		n := s.CvssV3.BaseScore
		switch {
		case n >= 9.0:
			return "critical"
		case n >= 7.0:
			return "high"
		case n >= 4.0:
			return "medium"
		case n > 0:
			return "low"
		}
	}
	return "unknown"
}

// firstDescription finds the first note with category "description".
func firstDescription(v *Vulnerability) string {
	for _, n := range v.Notes {
		if strings.EqualFold(n.Category, "description") && strings.TrimSpace(n.Text) != "" {
			return n.Text
		}
	}
	return ""
}

// preferSelfOrAdvisoryURL finds the most relevant advisory link.
func preferSelfOrAdvisoryURL(v *Vulnerability) string {
	for _, r := range v.References {
		if strings.EqualFold(r.Category, "advisory") && r.URL != "" {
			return r.URL
		}
	}
	for _, r := range v.References {
		if strings.EqualFold(r.Category, "self") && r.URL != "" {
			return r.URL
		}
	}
	return ""
}

// ConvertToJsonSecurityNotice 转换UnifiedAdvisory为JsonSecurityNotice
func ConvertToJsonSecurityNotice(ua *UnifiedAdvisory) JsonSecurityNotice {
	if ua == nil {
		return JsonSecurityNotice{}
	}

	// 处理Type：Severity映射为整数
	severityToType := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"unknown":  0,
	}
	noticeType := severityToType[ua.Severity]

	// 处理AffectedComponent：收集所有Packages.Name的去重集合并拼接
	pkgNameSet := make(map[string]struct{})
	for _, prod := range ua.Products {
		for _, pkg := range prod.Packages {
			if pkg.Name != "" {
				pkgNameSet[pkg.Name] = struct{}{}
			}
		}
	}
	var affectedComponents []string
	for name := range pkgNameSet {
		affectedComponents = append(affectedComponents, name)
	}
	affectedComponentStr := strings.Join(affectedComponents, ", ")

	// 处理Files：按Architecture分组，转换为[]File
	// key: Architecture, value: 该架构下的RpmFile列表
	archFilesMap := make(map[string][]RpmFile)
	for _, prod := range ua.Products {
		for _, pkg := range prod.Packages {
			// 构建RpmFile（FileName对应PackageInfo.Name，Version对应FixedVersion，FileURL暂空）
			rpmFile := RpmFile{
				FileName: pkg.Name,
				Version:  pkg.FixedVersion,
				FileURL:  "", // 原数据中无FileURL，暂为空
			}
			// 按架构分组（默认架构为"unknown"）
			arch := pkg.Architecture
			if arch == "" {
				arch = "unknown"
			}
			archFilesMap[arch] = append(archFilesMap[arch], rpmFile)
		}
	}
	// 转换map为[]File
	var files []File
	for arch, rpmList := range archFilesMap {
		files = append(files, File{
			Arch: arch,
			List: rpmList,
		})
	}

	// 处理AffectedProduct：拼接产品名称
	var affectedProducts []string
	for _, prod := range ua.Products {
		affectedProducts = append(affectedProducts, prod.Name)
	}
	affectedProductStr := strings.Join(affectedProducts, ", ")

	// 处理CVEList：转换为带CveID的结构（URL暂空）
	var cveList []CVE
	for _, cveID := range ua.CVEs {
		cveList = append(cveList, CVE{
			CveID: cveID,
			URL:   "", // 原数据中无CVE的URL，暂为空
		})
	}

	// 处理ReferenceList
	var referenceList []struct {
		URL string `json:"url"`
	}
	for _, refURL := range ua.References {
		referenceList = append(referenceList, struct {
			URL string `json:"url"`
		}{URL: refURL})
	}

	// 处理NoticeURL（取第一个参考链接）
	var noticeURL string
	if len(ua.References) > 0 {
		noticeURL = ua.References[0]
	}

	return JsonSecurityNotice{
		ID:                0, // 通常由存储层生成，此处暂为0
		SecurityNoticeNo:  ua.ID,
		NoticeURL:         noticeURL,
		Summary:           ua.Title,
		Type:              noticeType,
		AffectedProduct:   affectedProductStr,
		AffectedComponent: affectedComponentStr,
		AnnouncementTime:  ua.IssuedDate,
		Description:       ua.Description,
		Introduction:      ua.Description, // 复用Description作为Introduction
		CVEList:           cveList,
		Files:             files, // 核心转换：按架构分组的包信息
		ReferenceList:     referenceList,
		Subject:           ua.Title,
	}
}
