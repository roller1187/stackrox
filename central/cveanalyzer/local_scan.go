package cveanalyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type triggerResponse struct {
	ReportID    string `json:"reportID"`
	RequestName string `json:"requestName"`
}

type reportSnapshot struct {
	ReportJobID         string `json:"reportJobId"`
	Name                string `json:"name"`
	IsDownloadAvailable bool   `json:"isDownloadAvailable"`
	ReportStatus        struct {
		RunState    string `json:"runState"`
		ErrorMsg    string `json:"errorMsg"`
		CompletedAt string `json:"completedAt"`
	} `json:"reportStatus"`
}

type historyResponse struct {
	ReportSnapshots []reportSnapshot `json:"reportSnapshots"`
}

func (h *handler) fetchLocalCSV(ctx context.Context, authHeader string) ([]byte, error) {
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	base := "https://localhost:8443"

	triggerBody := `{"type":"VULNERABILITY","viewBasedVulnReportFilters":{"query":""}}`
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v2/reports/view-based/run", strings.NewReader(triggerBody))
	if err != nil {
		return nil, fmt.Errorf("creating trigger request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("triggering report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("trigger failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var triggerResp triggerResponse
	if err := json.NewDecoder(resp.Body).Decode(&triggerResp); err != nil {
		return nil, fmt.Errorf("decoding trigger response: %w", err)
	}
	reportID := triggerResp.ReportID
	if reportID == "" {
		return nil, fmt.Errorf("no report ID in trigger response")
	}

	log.Infof("CVE Analyzer: triggered local V2 report %s (%s), polling for completion", reportID, triggerResp.RequestName)

	for i := 0; i < 120; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}

		hReq, _ := http.NewRequestWithContext(ctx, "GET", base+"/v2/reports/view-based/my-history", nil)
		hReq.Header.Set("Authorization", authHeader)
		hResp, err := client.Do(hReq)
		if err != nil {
			continue
		}

		var history historyResponse
		json.NewDecoder(hResp.Body).Decode(&history)
		hResp.Body.Close()

		for _, s := range history.ReportSnapshots {
			if s.ReportJobID == reportID {
				switch s.ReportStatus.RunState {
				case "DELIVERED", "GENERATED":
					if s.IsDownloadAvailable {
						return h.downloadReport(ctx, client, base, reportID, authHeader)
					}
				case "FAILURE":
					return nil, fmt.Errorf("V2 report failed: %s", s.ReportStatus.ErrorMsg)
				}
				break
			}
		}
	}

	return nil, fmt.Errorf("timed out waiting for V2 report to complete (10 minutes)")
}

func (h *handler) downloadReport(ctx context.Context, client *http.Client, base, reportID, authHeader string) ([]byte, error) {
	dReq, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/reports/jobs/download?id="+reportID, nil)
	dReq.Header.Set("Authorization", authHeader)
	dResp, err := client.Do(dReq)
	if err != nil {
		return nil, fmt.Errorf("downloading report: %w", err)
	}
	defer dResp.Body.Close()

	if dResp.StatusCode != 200 {
		body, _ := io.ReadAll(dResp.Body)
		return nil, fmt.Errorf("download failed (HTTP %d): %s", dResp.StatusCode, string(body))
	}

	zipData, err := io.ReadAll(dResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading download body: %w", err)
	}

	return extractCSVFromZip(zipData)
}

func extractCSVFromZip(zipData []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening ZIP: %w", err)
	}

	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening CSV in ZIP: %w", err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("no CSV file found in ZIP")
}
