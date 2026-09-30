// Package validation provides a post-deployment runtime validation framework
// for the CVE Analyzer. It connects to a live Central instance, fetches report
// data, and verifies that all generated URLs are valid and reachable.
//
// Usage:
//
//	go run ./central/cveanalyzer/validation \
//	    -endpoint https://central-rhacs-operator.apps.example.com \
//	    -token "$ROX_API_TOKEN"
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type report struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	RecordCount *int   `json:"record_count"`
}

type record struct {
	Key            string `json:"key"`
	CVE            string `json:"cve"`
	ImageFull      string `json:"image_full"`
	ImageShort     string `json:"image_short"`
	ImageCatalogURL string `json:"image_catalog_url"`
	FixCatalogURL  string `json:"fix_catalog_url"`
	FixLatestRef   string `json:"fix_latest_ref"`
	FixStatus      string `json:"fix_status"`
	RoxStatus      string `json:"rox_status"`
	RHCVSS         string `json:"rh_cvss"`
	RHSeverity     string `json:"rh_severity"`
	PrimaryLink    string `json:"primary_link"`
	SecondaryLink  string `json:"secondary_link"`
	AdvisoryLink   string `json:"advisory_link"`
}

type urlCheck struct {
	Field    string
	URL      string
	ImageRef string
	CVE      string
}

type urlResult struct {
	urlCheck
	Status int
	Error  string
	OK     bool
}

func main() {
	endpoint := flag.String("endpoint", os.Getenv("ROX_ENDPOINT"), "Central endpoint URL (or ROX_ENDPOINT env)")
	token := flag.String("token", os.Getenv("ROX_API_TOKEN"), "API token (or ROX_API_TOKEN env)")
	password := flag.String("password", os.Getenv("ROX_PASSWORD"), "Admin password for basic auth (or ROX_PASSWORD env)")
	reportID := flag.String("report", "", "Specific report ID to validate (default: all completed reports)")
	workers := flag.Int("workers", 10, "Concurrent HTTP workers for URL validation")
	skipReachability := flag.Bool("skip-reachability", false, "Only validate URL format, skip HTTP checks")
	flag.Parse()

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: -endpoint or ROX_ENDPOINT required")
		os.Exit(1)
	}
	if *token == "" && *password == "" {
		fmt.Fprintln(os.Stderr, "Error: -token or -password required")
		os.Exit(1)
	}

	base := strings.TrimRight(*endpoint, "/")
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	apiGet := func(path string, v interface{}) error {
		req, err := http.NewRequest("GET", base+"/api/v1/cve-analyzer"+path, nil)
		if err != nil {
			return err
		}
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		} else {
			req.SetBasicAuth("admin", *password)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}

	// Fetch reports
	var reports []report
	if err := apiGet("/reports", &reports); err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching reports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d reports\n", len(reports))

	// Filter to completed reports with data
	var targetReports []report
	for _, r := range reports {
		if *reportID != "" && r.ID != *reportID {
			continue
		}
		if r.Status != "complete" && r.Status != "error" {
			continue
		}
		if r.RecordCount == nil || *r.RecordCount == 0 {
			continue
		}
		targetReports = append(targetReports, r)
	}

	if len(targetReports) == 0 {
		fmt.Println("No completed reports with data found")
		os.Exit(0)
	}

	// Collect all URLs to check
	var allChecks []urlCheck
	var totalRecords int

	for _, rpt := range targetReports {
		fmt.Printf("\nReport: %s (%s) — %d records\n", rpt.Name, rpt.ID[:8], *rpt.RecordCount)

		var records []record
		if err := apiGet(fmt.Sprintf("/reports/%s/data", rpt.ID), &records); err != nil {
			fmt.Fprintf(os.Stderr, "  Error fetching data: %v\n", err)
			continue
		}
		totalRecords += len(records)

		// Validate each record's URLs
		for _, rec := range records {
			if rec.ImageCatalogURL != "" {
				allChecks = append(allChecks, urlCheck{
					Field: "image_catalog_url", URL: rec.ImageCatalogURL,
					ImageRef: rec.ImageFull, CVE: rec.CVE,
				})
			}
			if rec.FixCatalogURL != "" {
				allChecks = append(allChecks, urlCheck{
					Field: "fix_catalog_url", URL: rec.FixCatalogURL,
					ImageRef: rec.FixLatestRef, CVE: rec.CVE,
				})
			}
			if rec.PrimaryLink != "" {
				allChecks = append(allChecks, urlCheck{
					Field: "primary_link", URL: rec.PrimaryLink,
					CVE: rec.CVE,
				})
			}
			if rec.AdvisoryLink != "" {
				allChecks = append(allChecks, urlCheck{
					Field: "advisory_link", URL: rec.AdvisoryLink,
					CVE: rec.CVE,
				})
			}
		}

		// --- Format validation (always runs) ---
		fmt.Println("  Format validation:")
		formatIssues := 0
		enrichmentGaps := 0

		for _, rec := range records {
			issues := validateRecordFormat(rec)
			formatIssues += len(issues)
			for _, issue := range issues {
				fmt.Printf("    FAIL  %s [%s]: %s\n", rec.CVE, rec.ImageShort, issue)
			}

			gaps := checkEnrichmentGaps(rec)
			enrichmentGaps += len(gaps)
			for _, gap := range gaps {
				fmt.Printf("    WARN  %s [%s]: %s\n", rec.CVE, rec.ImageShort, gap)
			}
		}
		if formatIssues == 0 {
			fmt.Printf("    OK    All %d records have valid URL formats\n", len(records))
		} else {
			fmt.Printf("    %d format issues found\n", formatIssues)
		}
		if enrichmentGaps > 0 {
			fmt.Printf("    %d enrichment gaps (missing expected data)\n", enrichmentGaps)
		}
	}

	// --- Reachability validation (optional) ---
	if *skipReachability {
		fmt.Println("\nSkipping reachability checks (-skip-reachability)")
		return
	}

	// Deduplicate URLs
	seen := make(map[string]bool)
	var uniqueChecks []urlCheck
	for _, c := range allChecks {
		if !seen[c.URL] {
			seen[c.URL] = true
			uniqueChecks = append(uniqueChecks, c)
		}
	}

	fmt.Printf("\nReachability validation: %d unique URLs from %d records\n", len(uniqueChecks), totalRecords)

	// Check URLs concurrently
	extClient := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	results := make([]urlResult, len(uniqueChecks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)

	for i, check := range uniqueChecks {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, c urlCheck) {
			defer wg.Done()
			defer func() { <-sem }()

			r := urlResult{urlCheck: c}
			req, err := http.NewRequest("HEAD", c.URL, nil)
			if err != nil {
				r.Error = err.Error()
				results[idx] = r
				return
			}
			req.Header.Set("User-Agent", "RHACS-CVE-Analyzer-Validation/1.0")

			resp, err := extClient.Do(req)
			if err != nil {
				r.Error = err.Error()
				results[idx] = r
				return
			}
			resp.Body.Close()
			r.Status = resp.StatusCode
			r.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
			results[idx] = r
		}(i, check)
	}
	wg.Wait()

	// Report results
	passed := 0
	failed := 0
	errored := 0
	failedByField := make(map[string]int)

	for _, r := range results {
		if r.OK {
			passed++
		} else if r.Error != "" {
			errored++
		} else {
			failed++
			failedByField[r.Field]++
			fmt.Printf("  FAIL  [%d] %s — %s (%s)\n", r.Status, r.Field, truncate(r.URL, 80), r.CVE)
		}
	}

	fmt.Printf("\n--- Results ---\n")
	fmt.Printf("Passed:  %d\n", passed)
	fmt.Printf("Failed:  %d\n", failed)
	fmt.Printf("Errors:  %d\n", errored)
	fmt.Printf("Total:   %d\n", len(results))

	if len(failedByField) > 0 {
		fmt.Println("\nFailures by field:")
		for field, count := range failedByField {
			fmt.Printf("  %s: %d\n", field, count)
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}

func validateRecordFormat(rec record) []string {
	var issues []string

	if rec.ImageCatalogURL != "" {
		if err := validateURLFormat(rec.ImageCatalogURL); err != nil {
			issues = append(issues, fmt.Sprintf("image_catalog_url malformed: %v", err))
		}
	}

	if rec.FixCatalogURL != "" {
		if err := validateURLFormat(rec.FixCatalogURL); err != nil {
			issues = append(issues, fmt.Sprintf("fix_catalog_url malformed: %v", err))
		}
	}

	if rec.PrimaryLink != "" {
		if err := validateURLFormat(rec.PrimaryLink); err != nil {
			issues = append(issues, fmt.Sprintf("primary_link malformed: %v", err))
		}
	}

	// Quay digest URLs should contain full sha256
	if rec.ImageCatalogURL != "" && strings.Contains(rec.ImageCatalogURL, "quay.io") {
		if strings.Contains(rec.ImageCatalogURL, "/manifest/") {
			if !strings.Contains(rec.ImageCatalogURL, "sha256:") {
				issues = append(issues, "quay manifest URL missing sha256: prefix")
			}
		}
	}

	// Catalog.redhat.com URLs should have the repo path
	if rec.ImageCatalogURL != "" && strings.Contains(rec.ImageCatalogURL, "catalog.redhat.com") {
		if !strings.Contains(rec.ImageCatalogURL, "/software/containers/") {
			issues = append(issues, "catalog URL missing /software/containers/ path")
		}
	}

	return issues
}

func checkEnrichmentGaps(rec record) []string {
	var gaps []string

	if strings.HasPrefix(rec.CVE, "CVE-") && rec.RHCVSS == "" {
		gaps = append(gaps, "missing rh_cvss")
	}
	if strings.HasPrefix(rec.CVE, "CVE-") && rec.RHSeverity == "" {
		gaps = append(gaps, "missing rh_severity")
	}
	if rec.RoxStatus == "" {
		gaps = append(gaps, "missing rox_status (current image scan)")
	}
	if rec.FixStatus == "" && !strings.Contains(rec.ImageFull, "ocp-v4.0-art-dev") {
		gaps = append(gaps, "missing fix_status (latest image scan)")
	}

	return gaps
}

func validateURLFormat(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
