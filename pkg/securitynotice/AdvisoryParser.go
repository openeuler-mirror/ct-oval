package securitynotice

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
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

// --- 2. Parser Interface (Unchanged) ---
// This interface defines the contract for all future advisory parsers.

type AdvisoryParser interface {
	Parse(filePath string) (*UnifiedAdvisory, error)
}

// --- 3. CSAF Implementation (Updated with your code) ---

// CSAFParser is a parser for openEuler CSAF JSON files.
type CSAFParser struct{}

var _ AdvisoryParser = (*CSAFParser)(nil)

// Parse reads a CSAF file, validates it, and transforms it into the generic UnifiedAdvisory format.
// This function now uses your more detailed CSAFDoc struct and helper functions.
func (p *CSAFParser) Parse(filePath string) (*UnifiedAdvisory, error) {
	// Step A: Parse the JSON into the new, more detailed CSAFDoc struct.
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var csafDoc CSAFDoc
	if err := json.Unmarshal(byteValue, &csafDoc); err != nil {
		return nil, err
	}

	// Step B: Transform the CSAF-specific data into the unified, generic format.
	return p.transform(csafDoc)
}

// transform now uses your helper functions to map data from CSAFDoc to UnifiedAdvisory.
func (p *CSAFParser) transform(doc CSAFDoc) (*UnifiedAdvisory, error) {
	v := firstVuln(doc)
	if v == nil || strings.TrimSpace(v.CVE) == "" {
		return nil, fmt.Errorf("CSAF document contains no valid vulnerability entry")
	}

	// Build the UnifiedAdvisory struct
	unified := &UnifiedAdvisory{
		ID:          doc.Document.Tracking.ID,
		Title:       doc.Document.Title,
		Description: firstDescription(v),
		Severity:    bucketSeverityFromScores(v),
		IssuedDate:  pickIssuedDate(doc), // <-- ADDED: Populate the issue date.
		CVEs:        []string{v.CVE},
	}

	// Extract references
	if advURL := preferSelfOrAdvisoryURL(v); advURL != "" {
		unified.References = append(unified.References, advURL)
	}
	for _, ref := range v.References {
		if ref.URL != "" {
			unified.References = append(unified.References, ref.URL)
		}
	}

	// Map product IDs to product names for human-readable output
	productNames := prodNameMap(doc)
	productsMap := make(map[string]AffectedProduct)

	// Process remediations to find fixed packages
	for _, rem := range v.Remediations {
		if !strings.EqualFold(rem.Category, "vendor_fix") {
			continue
		}

		// Your new regex-based package extraction is more robust.
		for _, pf := range extractPkgFixes(rem.Details) {
			pkgInfo := PackageInfo{
				Name:         pf.pkg,
				FixedVersion: pf.fixed,
				Architecture: "unknown", // CSAF remediation details often omit architecture
			}

			// Associate the package with all relevant product IDs
			for _, prodID := range rem.ProductIDs {
				product, exists := productsMap[prodID]
				if !exists {
					// Use the friendly name from the product tree if available
					name, hasName := productNames[prodID]
					if !hasName {
						name = prodID // fallback to ID
					}
					product = AffectedProduct{Name: name}
				}
				product.Packages = append(product.Packages, pkgInfo)
				productsMap[prodID] = product
			}
		}
	}

	for _, product := range productsMap {
		unified.Products = append(unified.Products, product)
	}

	return unified, nil
}

// --- Your CSAFDoc Struct and Helper Functions ---
// I've integrated your new struct and all helper functions directly.
// They are now used internally by the CSAFParser.

// CSAFDoc is a more detailed struct for parsing CSAF v2.0 JSON files.
type CSAFDoc struct {
	Document struct {
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		FullProductNames []struct {
			ProductID string `json:"product_id"`
			Name      string `json:"name"`
		} `json:"full_product_names"`
	} `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is a sub-struct for CSAFDoc.
type Vulnerability struct {
	CVE           string `json:"cve"`
	Title         string `json:"title"`
	Notes         []struct {
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

// prodNameMap creates a lookup map from product_id to product name.
func prodNameMap(doc CSAFDoc) map[string]string {
	m := map[string]string{}
	for _, p := range doc.ProductTree.FullProductNames {
		if p.ProductID != "" && p.Name != "" {
			m[p.ProductID] = p.Name
		}
	}
	return m
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

var rxPkgFix = regexp.MustCompile(`(?i)\b(?:pkg|package|update|upgrade|fix|fixed)[:\s-]*([a-z0-9+_.-]+)\s*(?:to|>=|version|:)?\s*([0-9][A-Za-z0-9._:+~-]+)`)

type pkgFix struct{ pkg, fixed string }

// extractPkgFixes uses regex to find package names and fixed versions in text.
func extractPkgFixes(details string) (out []pkgFix) {
	for _, m := range rxPkgFix.FindAllStringSubmatch(details, -1) {
		pkg := strings.TrimSpace(m[1])
		ver := strings.TrimSpace(m[2])
		if pkg != "" && ver != "" {
			out = append(out, pkgFix{pkg: pkg, fixed: ver})
		}
	}
	return
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

