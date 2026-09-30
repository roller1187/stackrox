package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

type rhCVEData struct {
	Score           float64                      `json:"score"`
	Vector          string                       `json:"vector"`
	Severity        string                       `json:"severity"`
	Mitigation      string                       `json:"mitigation"`
	Statement       string                       `json:"statement"`
	PublicDate      string                       `json:"public_date"`
	PackageState    map[string]rhPackageFixState `json:"package_state"`
	AffectedRelease map[string]rhAffectedRelease `json:"affected_release"`
	NotFound        bool
}

type rhPackageFixState struct {
	FixState    string `json:"fix_state"`
	ProductName string `json:"product_name"`
}

type rhAffectedRelease struct {
	Advisory    string `json:"advisory"`
	ProductName string `json:"product_name"`
}

// EnrichRedHatScores fetches CVSS scores and metadata from the Red Hat CVE API.
func EnrichRedHatScores(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	uniqueCVEs := make(map[string]bool)
	for _, r := range records {
		if len(r.CVE) > 4 && r.CVE[:4] == "CVE-" {
			uniqueCVEs[r.CVE] = true
		}
	}

	logf("  Fetching Red Hat scores for %d unique CVEs", len(uniqueCVEs))

	results := make(map[string]*rhCVEData)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for cve := range uniqueCVEs {
		wg.Add(1)
		sem <- struct{}{}
		go func(cveID string) {
			defer wg.Done()
			defer func() { <-sem }()

			data := fetchRHCVE(ctx, cveID)
			mu.Lock()
			results[cveID] = data
			mu.Unlock()
		}(cve)
	}
	wg.Wait()

	found := 0
	for i := range records {
		r := &records[i]
		data, ok := results[r.CVE]

		// Enrich RH metadata when available
		if ok && data != nil && !data.NotFound {
			if data.Score > 0 {
				r.RHCVSS = fmt.Sprintf("%.1f", data.Score)
				found++
			}
			if data.Vector != "" {
				r.RHVector = data.Vector
			}
			if data.Severity != "" {
				r.RHSeverity = data.Severity
			}
			if data.Mitigation != "" {
				r.RHMitigation = data.Mitigation
			}
			if data.Statement != "" {
				r.RHStatement = data.Statement
			}
			if data.PublicDate != "" {
				r.CVEPublished = data.PublicDate
			}

			if strings.HasPrefix(r.ImageFull, "registry.redhat.io/") {
				ref := r.ImageFull
				if idx := strings.Index(ref, "@"); idx >= 0 {
					ref = ref[:idx]
				} else if idx := strings.LastIndex(ref, ":"); idx >= 0 {
					ref = ref[:idx]
				}
				pkgName := strings.TrimPrefix(ref, "registry.redhat.io/")

				if ar, ok := data.AffectedRelease[pkgName]; ok {
					r.RHFixState = "Fix Available"
					r.RHFixStateDetail = ar.Advisory
				} else if ps, ok := data.PackageState[pkgName]; ok {
					r.RHFixState = ps.FixState
					r.RHFixStateDetail = ps.ProductName
				}
			}
		}

		// Link priority: RH CVE page > NVD > OSV when in RH DB; NVD > OSV when not
		rhNotFound := !ok || data == nil || data.NotFound
		if strings.HasPrefix(r.CVE, "CVE-") {
			if rhNotFound {
				r.PrimaryLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", r.CVE)
				r.SecondaryLink = fmt.Sprintf("https://osv.dev/vulnerability/%s", r.CVE)
				r.TertiaryLink = ""
			} else {
				r.PrimaryLink = fmt.Sprintf("https://access.redhat.com/security/cve/%s", r.CVE)
				r.SecondaryLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", r.CVE)
				r.TertiaryLink = fmt.Sprintf("https://osv.dev/vulnerability/%s", r.CVE)
			}
		} else if strings.HasPrefix(r.CVE, "GHSA-") {
			r.PrimaryLink = fmt.Sprintf("https://osv.dev/vulnerability/%s", r.CVE)
			r.SecondaryLink = fmt.Sprintf("https://github.com/advisories/%s", r.CVE)
			r.TertiaryLink = ""
		}
	}

	logf("  Red Hat scores: %d/%d CVEs enriched", found, len(uniqueCVEs))
}

func fetchRHCVE(ctx context.Context, cveID string) *rhCVEData {
	url := fmt.Sprintf("https://access.redhat.com/hydra/rest/securitydata/cve/%s.json", cveID)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &rhCVEData{}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "StackRox-CVE-Analyzer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &rhCVEData{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return &rhCVEData{NotFound: true}
	}
	if resp.StatusCode != 200 {
		return &rhCVEData{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &rhCVEData{}
	}

	var raw struct {
		CVSS3 struct {
			BaseScore     json.Number `json:"cvss3_base_score"`
			ScoringVector string      `json:"cvss3_scoring_vector"`
		} `json:"cvss3"`
		ThreatSeverity string      `json:"threat_severity"`
		Mitigation     interface{} `json:"mitigation"`
		Statement      interface{} `json:"statement"`
		PublicDate     string      `json:"public_date"`
		PackageState []struct {
			PackageName string `json:"package_name"`
			FixState    string `json:"fix_state"`
			ProductName string `json:"product_name"`
		} `json:"package_state"`
		AffectedRelease []struct {
			Package     string `json:"package"`
			Advisory    string `json:"advisory"`
			ProductName string `json:"product_name"`
		} `json:"affected_release"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return &rhCVEData{}
	}

	score, _ := raw.CVSS3.BaseScore.Float64()

	mitText := ""
	if m, ok := raw.Mitigation.(map[string]interface{}); ok {
		if v, ok := m["value"].(string); ok {
			mitText = v
		}
	}

	stmtText := ""
	if s, ok := raw.Statement.(string); ok {
		stmtText = s
	}

	pubDate := raw.PublicDate
	if idx := findByte(pubDate, 'T'); idx >= 0 {
		pubDate = pubDate[:idx]
	}

	fixStateRank := map[string]int{
		"Affected": 5, "New": 4, "Fix deferred": 3,
		"Will not fix": 2, "Out of support scope": 1, "Not affected": 0,
	}
	pkgState := make(map[string]rhPackageFixState)
	for _, ps := range raw.PackageState {
		if ps.PackageName == "" || ps.FixState == "" {
			continue
		}
		existing, ok := pkgState[ps.PackageName]
		if !ok || fixStateRank[ps.FixState] > fixStateRank[existing.FixState] {
			pkgState[ps.PackageName] = rhPackageFixState{
				FixState:    ps.FixState,
				ProductName: ps.ProductName,
			}
		}
	}

	affectedRelease := make(map[string]rhAffectedRelease)
	for _, ar := range raw.AffectedRelease {
		pkgKey := ar.Package
		if idx := strings.Index(pkgKey, ":"); idx >= 0 {
			pkgKey = pkgKey[:idx]
		}
		if pkgKey == "" {
			continue
		}
		if _, exists := affectedRelease[pkgKey]; !exists {
			affectedRelease[pkgKey] = rhAffectedRelease{
				Advisory:    ar.Advisory,
				ProductName: ar.ProductName,
			}
		}
	}

	return &rhCVEData{
		Score:           score,
		Vector:          raw.CVSS3.ScoringVector,
		Severity:        raw.ThreatSeverity,
		Mitigation:      mitText,
		Statement:       stmtText,
		PublicDate:      pubDate,
		PackageState:    pkgState,
		AffectedRelease: affectedRelease,
	}
}

func findByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
