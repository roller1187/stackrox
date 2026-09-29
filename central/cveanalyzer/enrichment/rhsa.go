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

// EnrichRHSADescriptions fetches advisory descriptions from the Red Hat security API.
func EnrichRHSADescriptions(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	uniqueRHSAs := make(map[string]bool)
	for _, r := range records {
		if r.RHSAAdvisory != "" {
			uniqueRHSAs[r.RHSAAdvisory] = true
		}
	}

	if len(uniqueRHSAs) == 0 {
		logf("  No RHSA advisories to fetch")
		return
	}

	logf("  Fetching descriptions for %d unique RHSA advisories", len(uniqueRHSAs))

	type rhsaResult struct {
		Description string
		Link        string
	}

	results := make(map[string]*rhsaResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for rhsa := range uniqueRHSAs {
		wg.Add(1)
		sem <- struct{}{}
		go func(advisory string) {
			defer wg.Done()
			defer func() { <-sem }()

			desc, link := fetchRHSA(ctx, advisory)
			mu.Lock()
			results[advisory] = &rhsaResult{Description: desc, Link: link}
			mu.Unlock()
		}(rhsa)
	}
	wg.Wait()

	for i := range records {
		r := &records[i]
		if res, ok := results[r.RHSAAdvisory]; ok {
			r.RHSADescription = res.Description
			if r.AdvisoryLink == "" && res.Link != "" {
				r.AdvisoryLink = res.Link
			}
		}
	}

	logf("  Fetched %d RHSA descriptions", len(results))
}

func fetchRHSA(ctx context.Context, advisory string) (description, link string) {
	url := fmt.Sprintf("https://access.redhat.com/hydra/rest/securitydata/cvrf/%s.json", advisory)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "StackRox-CVE-Analyzer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}

	var raw struct {
		CvrfDoc struct {
			DocumentNotes []struct {
				Note string `json:"Note"`
				Type string `json:"Type"`
			} `json:"DocumentNotes"`
			DocumentReferences []struct {
				URL  string `json:"URL"`
				Type string `json:"Type"`
			} `json:"DocumentReferences"`
		} `json:"cvrfdoc"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return "", ""
	}

	for _, note := range raw.CvrfDoc.DocumentNotes {
		if note.Type == "General" || note.Type == "Description" {
			if len(note.Note) > 0 && len(note.Note) < 500 {
				description = note.Note
				break
			}
		}
	}

	for _, ref := range raw.CvrfDoc.DocumentReferences {
		if ref.Type == "Self" {
			link = ref.URL
			break
		}
	}

	if link == "" {
		link = fmt.Sprintf("https://access.redhat.com/errata/%s", advisory)
	}

	return description, link
}
