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

type osvResponse struct {
	ID       string        `json:"id"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []map[string]string `json:"events"`
}

type osvResult struct {
	status       string
	affectedRange string
}

func queryOSV(ctx context.Context, client *http.Client, cveID string) osvResult {
	if !strings.HasPrefix(cveID, "CVE-") && !strings.HasPrefix(cveID, "GHSA-") {
		return osvResult{}
	}

	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return osvResult{status: "OSV error"}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return osvResult{status: "OSV error"}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return osvResult{status: "Not in OSV"}
	}
	if resp.StatusCode != 200 {
		return osvResult{status: fmt.Sprintf("OSV error (%d)", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return osvResult{status: "OSV error"}
	}

	var data osvResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return osvResult{status: "OSV error"}
	}

	if len(data.Affected) == 0 {
		return osvResult{status: "Not in OSV"}
	}

	var rangeStrs []string
	for _, a := range data.Affected {
		for _, r := range a.Ranges {
			var parts []string
			for _, e := range r.Events {
				for k, v := range e {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
			}
			if len(parts) > 0 {
				rangeStrs = append(rangeStrs, strings.Join(parts, ", "))
			}
		}
	}

	rangeStr := ""
	if len(rangeStrs) > 3 {
		rangeStrs = rangeStrs[:3]
	}
	rangeStr = strings.Join(rangeStrs, "; ")

	return osvResult{status: "Confirmed", affectedRange: rangeStr}
}

// EnrichOSV verifies CVEs against the OSV.dev database.
func EnrichOSV(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	uniqueCVEs := make(map[string]bool)
	for _, r := range records {
		if r.CVE != "" {
			uniqueCVEs[r.CVE] = true
		}
	}

	logf("  Verifying %d unique CVEs against OSV.dev", len(uniqueCVEs))

	client := &http.Client{Timeout: 10 * time.Second}
	cache := make(map[string]osvResult)
	var mu sync.Mutex

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for cve := range uniqueCVEs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := queryOSV(ctx, client, id)
			mu.Lock()
			cache[id] = result
			mu.Unlock()
		}(cve)
	}
	wg.Wait()

	confirmed := 0
	notFound := 0
	for i := range records {
		r := &records[i]
		if result, ok := cache[r.CVE]; ok {
			r.OSVVerification = result.status
			r.OSVAffectedRange = result.affectedRange
			if result.status == "Confirmed" {
				confirmed++
			} else if result.status == "Not in OSV" {
				notFound++
			}
		}
	}

	logf("  OSV: %d confirmed, %d not found, %d unique CVEs checked", confirmed, notFound, len(uniqueCVEs))
}
