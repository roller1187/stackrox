package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

type rhCVEData struct {
	Score      float64 `json:"score"`
	Vector     string  `json:"vector"`
	Severity   string  `json:"severity"`
	Mitigation string  `json:"mitigation"`
	Statement  string  `json:"statement"`
	PublicDate string  `json:"public_date"`
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
		if !ok || data == nil {
			continue
		}
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

		// Set primary link
		if r.PrimaryLink == "" {
			r.PrimaryLink = fmt.Sprintf("https://access.redhat.com/security/cve/%s", r.CVE)
		}
		r.SecondaryLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", r.CVE)
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
		return &rhCVEData{}
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

	return &rhCVEData{
		Score:      score,
		Vector:     raw.CVSS3.ScoringVector,
		Severity:   raw.ThreatSeverity,
		Mitigation: mitText,
		Statement:  stmtText,
		PublicDate: pubDate,
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
