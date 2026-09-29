package enrichment

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

const (
	fixStatusFixed       = "FIXED_IN_LATEST"
	fixStatusVulnerable  = "STILL_VULNERABLE"
	fixStatusUnavailable = "SCAN_UNAVAILABLE"
)

type scanResult struct {
	imageKey   string
	fixStatus  string
	fixTag     string
	fixRef     string
	scanError  string
	cveResults map[string]bool
}

// ScanLatestImages scans only the latest version of each image to check if CVEs are fixed.
// Per user requirement: we do NOT re-scan the current (vulnerable) image.
func ScanLatestImages(ctx context.Context, records []cveatypes.CVERecord, settings *cveatypes.Settings, logf func(string, ...interface{})) {
	type imageGroup struct {
		imageRef string
		indices  []int
	}
	groups := make(map[string]*imageGroup)
	var groupOrder []string

	for i, r := range records {
		if r.ImageFull == "" {
			continue
		}
		key := r.ImageFull
		if g, ok := groups[key]; ok {
			g.indices = append(g.indices, i)
		} else {
			groups[key] = &imageGroup{imageRef: r.ImageFull, indices: []int{i}}
			groupOrder = append(groupOrder, key)
		}
	}

	logf("  Scanning latest versions of %d unique images", len(groups))

	workers := settings.ScanWorkers
	if workers <= 0 {
		workers = 4
	}

	// Build the internal Central API URL
	centralURL := settings.RoxEndpoint
	if centralURL == "" {
		centralURL = "https://localhost:8443"
	}
	apiToken := settings.RoxAPIToken

	results := make(map[string]*scanResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for _, key := range groupOrder {
		g := groups[key]
		wg.Add(1)
		sem <- struct{}{}
		go func(img *imageGroup) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanLatestImage(ctx, img.imageRef, centralURL, apiToken, settings.SkipTLSVerify)
			mu.Lock()
			results[img.imageRef] = result
			mu.Unlock()
		}(g)
	}
	wg.Wait()

	fixed := 0
	vulnerable := 0
	unavailable := 0

	for _, key := range groupOrder {
		g := groups[key]
		result, ok := results[key]
		if !ok {
			continue
		}

		for _, idx := range g.indices {
			r := &records[idx]
			r.FixStatus = result.fixStatus
			r.FixLatestTag = result.fixTag
			r.FixLatestRef = result.fixRef
			r.FixScanError = result.scanError

			// Check if this specific CVE is fixed in the latest image
			if result.cveResults != nil {
				if stillPresent, checked := result.cveResults[r.CVE]; checked {
					if stillPresent {
						r.FixStatus = fixStatusVulnerable
					} else {
						r.FixStatus = fixStatusFixed
					}
				}
			}
		}

		switch result.fixStatus {
		case fixStatusFixed:
			fixed++
		case fixStatusVulnerable:
			vulnerable++
		default:
			unavailable++
		}
	}

	logf("  Scan results: %d fixed, %d vulnerable, %d unavailable (out of %d images)",
		fixed, vulnerable, unavailable, len(groups))
}

func scanLatestImage(ctx context.Context, imageRef, centralURL, apiToken string, skipTLS bool) *scanResult {
	result := &scanResult{
		imageKey:   imageRef,
		fixStatus:  fixStatusUnavailable,
		cveResults: make(map[string]bool),
	}

	// Derive the "latest" image reference from the current one
	latestRef := deriveLatestRef(imageRef)
	if latestRef == "" {
		result.scanError = "Could not determine latest image reference"
		return result
	}

	result.fixRef = latestRef
	result.fixTag = extractTag(latestRef)

	if centralURL == "" || apiToken == "" {
		result.scanError = "Central API endpoint or token not configured"
		return result
	}

	// Call Central's scan API to scan the latest image
	scanResp, err := callCentralScan(ctx, centralURL, apiToken, latestRef, skipTLS)
	if err != nil {
		result.scanError = fmt.Sprintf("Scan failed: %v", err)
		return result
	}

	// Parse scan results to find which CVEs are still present
	cveSet := extractCVEsFromScan(scanResp)
	result.cveResults = cveSet

	if len(cveSet) == 0 {
		result.fixStatus = fixStatusFixed
	} else {
		result.fixStatus = fixStatusVulnerable
	}

	return result
}

func deriveLatestRef(imageRef string) string {
	// For digest-based refs (image@sha256:...), convert to tag-based (:latest)
	if idx := strings.Index(imageRef, "@sha256:"); idx >= 0 {
		base := imageRef[:idx]
		return base + ":latest"
	}
	// For tag-based refs, use :latest
	if idx := strings.LastIndex(imageRef, ":"); idx >= 0 {
		base := imageRef[:idx]
		return base + ":latest"
	}
	return imageRef + ":latest"
}

func extractTag(ref string) string {
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		return ref[idx+1:]
	}
	return ""
}

func callCentralScan(ctx context.Context, centralURL, apiToken, imageRef string, skipTLS bool) (map[string]interface{}, error) {
	url := strings.TrimRight(centralURL, "/") + "/v1/images/scan"

	body, _ := json.Marshal(map[string]string{
		"imageName": imageRef,
	})

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Central scan API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Central scan API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding scan response: %w", err)
	}
	return result, nil
}

func extractCVEsFromScan(scanResp map[string]interface{}) map[string]bool {
	cves := make(map[string]bool)

	// Navigate the scan response structure to find CVEs
	// The response from /v1/images/scan has: scan.components[].vulns[].cve
	scan, ok := scanResp["scan"].(map[string]interface{})
	if !ok {
		return cves
	}

	components, ok := scan["components"].([]interface{})
	if !ok {
		return cves
	}

	for _, comp := range components {
		c, ok := comp.(map[string]interface{})
		if !ok {
			continue
		}
		vulns, ok := c["vulns"].([]interface{})
		if !ok {
			continue
		}
		for _, vuln := range vulns {
			v, ok := vuln.(map[string]interface{})
			if !ok {
				continue
			}
			if cveID, ok := v["cve"].(string); ok {
				cves[cveID] = true
			}
		}
	}

	return cves
}
