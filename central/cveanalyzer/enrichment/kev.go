package enrichment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stackrox/rox/pkg/logging"
)

var log = logging.LoggerForModule()

type kevCatalog struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID          string `json:"cveID"`
	DateAdded      string `json:"dateAdded"`
	DueDate        string `json:"dueDate"`
	VulnName       string `json:"vulnerabilityName"`
	ShortDesc      string `json:"shortDescription"`
	RequiredAction string `json:"requiredAction"`
}

// EnrichKEV checks CVEs against the CISA Known Exploited Vulnerabilities catalog.
func EnrichKEV(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	logf("  Fetching CISA KEV catalog")

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		logf("  WARNING: Failed to create KEV request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		logf("  WARNING: Failed to fetch KEV catalog: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logf("  WARNING: KEV catalog returned status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logf("  WARNING: Failed to read KEV catalog: %v", err)
		return
	}

	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		logf("  WARNING: Failed to parse KEV catalog: %v", err)
		return
	}

	kevMap := make(map[string]*kevEntry, len(catalog.Vulnerabilities))
	for i := range catalog.Vulnerabilities {
		kevMap[catalog.Vulnerabilities[i].CVEID] = &catalog.Vulnerabilities[i]
	}

	matched := 0
	for i := range records {
		r := &records[i]
		if entry, ok := kevMap[r.CVE]; ok {
			r.KEVDateAdded = entry.DateAdded
			r.KEVDueDate = entry.DueDate
			matched++

			// KEV vulnerabilities always get elevated priority
			if r.Priority == "P5-LOW" || r.Priority == "P4-MONITOR" {
				r.Priority = "P3-MODERATE"
				r.Action = "PATCH"
			}
		}
	}

	logf("  KEV: %d/%d CVEs found in catalog (%d total KEV entries)", matched, len(records), len(catalog.Vulnerabilities))
}
