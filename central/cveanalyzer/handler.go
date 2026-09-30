package cveanalyzer

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cveexport "github.com/stackrox/rox/central/cveanalyzer/export"
	"github.com/stackrox/rox/central/cveanalyzer/pipeline"
	"github.com/stackrox/rox/central/cveanalyzer/store"
	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/logging"
)

var (
	log = logging.LoggerForModule()
)

type handler struct {
	store    *store.Store
	pipeline *pipeline.Runner
}

// Handler returns the HTTP handler for the CVE Analyzer API.
func Handler() http.Handler {
	if !features.CveAnalyzer.Enabled() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "CVE Analyzer is not enabled", http.StatusNotFound)
		})
	}

	db := globaldb.GetPostgres()
	s := store.New(db)
	runner := pipeline.NewRunner(s)

	h := &handler{store: s, pipeline: runner}

	// Reset any reports stuck in running/queued from a previous Central restart
	if reports, err := s.ListReports(context.Background()); err == nil {
		for _, r := range reports {
			if r.Status == cveatypes.StatusRunning || r.Status == cveatypes.StatusQueued {
				_ = s.UpdateReportStatus(context.Background(), r.ID, cveatypes.StatusError, "", "Pipeline interrupted by Central restart")
				log.Infof("CVE Analyzer: reset stuck report %s (%s) from %s to error", r.ID, r.Name, r.Status)
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /reports", h.listReports)
	mux.HandleFunc("POST /reports/upload", h.uploadReport)
	mux.HandleFunc("POST /reports/analyze-local", h.analyzeLocal)
	mux.HandleFunc("POST /reports/{id}/analyze", h.analyzeReport)
	mux.HandleFunc("POST /reports/{id}/rebuild", h.analyzeReport)
	mux.HandleFunc("POST /reports/{id}/abort", h.abortReport)
	mux.HandleFunc("DELETE /reports/{id}", h.deleteReport)
	mux.HandleFunc("GET /reports/{id}/data", h.getReportData)
	mux.HandleFunc("GET /reports/{id}/state", h.getProcessedState)
	mux.HandleFunc("POST /reports/{id}/state", h.saveProcessedState)
	mux.HandleFunc("GET /reports/{id}/fp_state", h.getFPState)
	mux.HandleFunc("POST /reports/{id}/fp_state", h.saveFPState)
	mux.HandleFunc("GET /reports/{id}/notes", h.getNotes)
	mux.HandleFunc("POST /reports/{id}/notes", h.saveNotes)
	mux.HandleFunc("GET /reports/{id}/updates", h.getUpdates)
	mux.HandleFunc("POST /reports/{id}/updates/acknowledge", h.acknowledgeUpdates)
	mux.HandleFunc("GET /reports/{id}/export.csv", h.exportCSV)
	mux.HandleFunc("GET /reports/{id}/report.html", h.exportHTML)
	mux.HandleFunc("GET /reports/{id}/log", h.getLog)
	mux.HandleFunc("GET /settings", h.getSettings)
	mux.HandleFunc("POST /settings", h.saveSettings)
	mux.HandleFunc("POST /settings/test", h.testScanInternal)
	mux.HandleFunc("GET /settings/check", h.preflightCheck)

	return http.StripPrefix("/api/v1/cve-analyzer", mux)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- Report endpoints ---

func (h *handler) listReports(w http.ResponseWriter, r *http.Request) {
	reports, err := h.store.ListReports(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

func (h *handler) uploadReport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "Missing file field")
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		writeError(w, http.StatusBadRequest, "Only CSV files are accepted")
		return
	}

	csvData, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read file")
		return
	}

	// Validate CSV
	reader := csv.NewReader(strings.NewReader(string(csvData)))
	headers, err := reader.Read()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid CSV file")
		return
	}
	hasRequired := false
	for _, h := range headers {
		if h == "CVE" {
			hasRequired = true
			break
		}
	}
	if !hasRequired {
		writeError(w, http.StatusBadRequest, "CSV must contain a 'CVE' column (RHACS export format)")
		return
	}

	name := r.FormValue("name")
	if name == "" {
		name = strings.TrimSuffix(header.Filename, ".csv")
	}

	report, err := h.store.CreateReport(r.Context(), name, header.Filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create report: %v", err))
		return
	}

	if err := h.store.StoreRawCSV(r.Context(), report.ID, csvData); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store CSV: %v", err))
		return
	}

	// Start pipeline in background
	go h.pipeline.Run(report.ID, false)

	warnings := h.checkPreflightWarnings(r.Context())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":       report.ID,
		"name":     report.Name,
		"warnings": warnings,
	})
}

func (h *handler) analyzeLocal(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeError(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	name := fmt.Sprintf("Local Scan — %s", time.Now().Format("Jan 2, 2006 3:04 PM"))
	report, err := h.store.CreateReport(r.Context(), name, "local-export.csv")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create report: %v", err))
		return
	}

	go func() {
		ctx := context.Background()
		h.store.UpdateReportStatus(ctx, report.ID, cveatypes.StatusRunning, "Fetching vulnerability data from Central...", "")

		csvData, err := h.fetchLocalCSV(ctx, authHeader)
		if err != nil {
			log.Errorf("CVE Analyzer: local scan failed: %v", err)
			h.store.UpdateReportStatus(ctx, report.ID, cveatypes.StatusError, "", fmt.Sprintf("Failed to fetch CSV: %v", err))
			return
		}

		log.Infof("CVE Analyzer: local scan fetched %d bytes of CSV data", len(csvData))
		if err := h.store.StoreRawCSV(ctx, report.ID, csvData); err != nil {
			h.store.UpdateReportStatus(ctx, report.ID, cveatypes.StatusError, "", fmt.Sprintf("Failed to store CSV: %v", err))
			return
		}

		h.pipeline.Run(report.ID, false)
	}()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":   report.ID,
		"name": report.Name,
	})
}

func (h *handler) analyzeReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	report, err := h.store.GetReport(r.Context(), id)
	if err != nil || report == nil {
		writeError(w, http.StatusNotFound, "Report not found")
		return
	}
	if report.Status == cveatypes.StatusRunning || report.Status == cveatypes.StatusQueued {
		writeError(w, http.StatusConflict, "Pipeline already running")
		return
	}

	go h.pipeline.Run(id, report.CompletedAt != nil)

	warnings := h.checkPreflightWarnings(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"warnings": warnings,
	})
}

func (h *handler) abortReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.pipeline.Abort(id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) deleteReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.pipeline.Abort(id)
	if err := h.store.DeleteReport(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Data endpoints ---

func (h *handler) getReportData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	records, err := h.store.GetRecords(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, records)
}

// --- State endpoints ---

func (h *handler) getProcessedState(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.GetProcessedKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *handler) saveProcessedState(w http.ResponseWriter, r *http.Request) {
	var keys []string
	if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := h.store.SaveProcessedKeys(r.Context(), r.PathValue("id"), keys); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) getFPState(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.GetFPKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *handler) saveFPState(w http.ResponseWriter, r *http.Request) {
	var keys []string
	if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := h.store.SaveFPKeys(r.Context(), r.PathValue("id"), keys); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Notes ---

func (h *handler) getNotes(w http.ResponseWriter, r *http.Request) {
	notes, err := h.store.GetNotes(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, notes)
}

func (h *handler) saveNotes(w http.ResponseWriter, r *http.Request) {
	var notes map[string]string
	if err := json.NewDecoder(r.Body).Decode(&notes); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := h.store.SaveNotes(r.Context(), r.PathValue("id"), notes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Updates ---

func (h *handler) getUpdates(w http.ResponseWriter, r *http.Request) {
	updates, err := h.store.GetUpdates(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updates)
}

func (h *handler) acknowledgeUpdates(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := h.store.AcknowledgeUpdates(r.Context(), r.PathValue("id"), body.Keys); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Settings ---

func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.store.GetSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *handler) saveSettings(w http.ResponseWriter, r *http.Request) {
	var settings cveatypes.Settings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := h.store.SaveSettings(r.Context(), &settings); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) testScanInternal(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"output": "CVE Analyzer runs inside Central and uses internal scanning APIs. No external connection needed.",
	})
}

func (h *handler) preflightCheck(w http.ResponseWriter, r *http.Request) {
	warnings := h.checkPreflightWarnings(r.Context())
	writeJSON(w, http.StatusOK, cveatypes.PreflightResult{Warnings: warnings})
}

func (h *handler) checkPreflightWarnings(ctx interface{ Value(interface{}) interface{} }) []string {
	// Since we run inside Central, most checks pass automatically
	return []string{}
}

// --- Export ---

func (h *handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	records, err := h.store.GetRecords(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	report, _ := h.store.GetReport(r.Context(), id)
	filename := "export.csv"
	if report != nil {
		filename = strings.ReplaceAll(report.Name, " ", "_") + ".csv"
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	writer := csv.NewWriter(w)
	defer writer.Flush()

	notes, _ := h.store.GetNotes(r.Context(), id)

	headers := []string{"Processed", "False_Positive", "Note", "Priority", "Action", "CVE", "Severity", "CVSS", "RH_CVSS", "EPSS_Pct",
		"Product", "Image_Short", "Image_Full", "Cluster", "Namespaces", "Deployments",
		"Component", "Component_Version", "Fixed_In", "Fix_Status", "RH_Fix_State", "RH_Fix_State_Detail",
		"RHSA_Advisory", "Advisory_Link", "Primary_Link", "Remediation_Path",
		"Triage_Reasoning", "OSV_Verification", "POAM_Justification",
		"Discovered", "KEV_Date_Added", "KEV_Due_Date", "SLA_Deadline", "SLA_Tier"}
	writer.Write(headers)

	procKeys, _ := h.store.GetProcessedKeys(r.Context(), id)
	fpKeys, _ := h.store.GetFPKeys(r.Context(), id)
	procSet := make(map[string]bool, len(procKeys))
	for _, k := range procKeys {
		procSet[k] = true
	}
	fpSet := make(map[string]bool, len(fpKeys))
	for _, k := range fpKeys {
		fpSet[k] = true
	}

	for _, rec := range records {
		proc := ""
		if procSet[rec.Key] {
			proc = "Yes"
		}
		fp := ""
		if fpSet[rec.Key] {
			fp = "Yes"
		}
		note := notes[rec.Key]
		writer.Write([]string{
			proc, fp, note,
			rec.Priority, rec.Action, rec.CVE, rec.Severity, rec.CVSS, rec.RHCVSS, rec.EpssPct,
			rec.Product, rec.ImageShort, rec.ImageFull, rec.Cluster, rec.Namespaces, rec.Deployments,
			rec.Component, rec.ComponentVersion, rec.FixedIn, rec.FixStatus, rec.RHFixState, rec.RHFixStateDetail,
			rec.RHSAAdvisory, rec.AdvisoryLink, rec.PrimaryLink, rec.RemediationPath,
			rec.TriageReasoning, rec.OSVVerification, rec.POAMJustification,
			rec.Discovered, rec.KEVDateAdded, rec.KEVDueDate, rec.SLADeadline, rec.SLATier,
		})
	}
}

func (h *handler) exportHTML(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	records, err := h.store.GetRecords(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	report, _ := h.store.GetReport(r.Context(), id)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	cveexport.GenerateHTML(w, report, records)
}

func (h *handler) getLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	logText := h.pipeline.GetLog(id)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(logText))
}
