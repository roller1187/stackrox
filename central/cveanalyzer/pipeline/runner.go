package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/stackrox/rox/central/cveanalyzer/enrichment"
	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stackrox/rox/central/cveanalyzer/store"
	"github.com/stackrox/rox/pkg/logging"
)

var log = logging.LoggerForModule()

type Runner struct {
	store   *store.Store
	mu      sync.Mutex
	running map[string]context.CancelFunc
	logs    map[string]*strings.Builder
}

func NewRunner(s *store.Store) *Runner {
	return &Runner{
		store:   s,
		running: make(map[string]context.CancelFunc),
		logs:    make(map[string]*strings.Builder),
	}
}

func (r *Runner) IsRunning(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.running[id]
	return ok
}

func (r *Runner) Abort(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel, ok := r.running[id]; ok {
		cancel()
		delete(r.running, id)
	}
}

func (r *Runner) GetLog(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sb, ok := r.logs[id]; ok {
		return sb.String()
	}
	return "No log available."
}

func (r *Runner) Run(reportID string, isRegen bool) {
	ctx, cancel := context.WithCancel(context.Background())

	r.mu.Lock()
	if _, running := r.running[reportID]; running {
		r.mu.Unlock()
		cancel()
		return
	}
	r.running[reportID] = cancel
	logBuf := &strings.Builder{}
	r.logs[reportID] = logBuf
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.running, reportID)
		r.mu.Unlock()
		cancel()
	}()

	logf := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		log.Info(msg)
		logBuf.WriteString(time.Now().Format("15:04:05") + " " + msg + "\n")
	}

	logf("Pipeline starting for report %s (regen=%v)", reportID, isRegen)

	if err := r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusRunning, "Starting pipeline", ""); err != nil {
		logf("ERROR: Failed to update status: %v", err)
		return
	}

	settings, err := r.store.GetSettings(ctx)
	if err != nil {
		logf("ERROR: Failed to load settings: %v", err)
		r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusError, "", err.Error())
		return
	}

	// Get raw CSV
	csvData, err := r.store.GetRawCSV(ctx, reportID)
	if err != nil {
		logf("ERROR: Failed to load CSV data: %v", err)
		r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusError, "", "No CSV data found")
		return
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"Parsing CSV and computing priorities", nil},
		{"Fetching Red Hat CVSS scores", nil},
		{"Checking CISA KEV catalog", nil},
		{"Fetching RHSA descriptions", nil},
		{"Scanning latest image versions", nil},
		{"Computing SLA deadlines", nil},
		{"Detecting changes", nil},
	}

	var records []cveatypes.CVERecord

	// Step 1: Parse CSV and compute priorities
	steps[0].fn = func() error {
		var err error
		records, err = ParseAndTriage(csvData)
		if err != nil {
			return fmt.Errorf("parsing CSV: %w", err)
		}
		logf("  Parsed %d records from CSV", len(records))
		return nil
	}

	// Step 2: Fetch Red Hat CVSS scores
	steps[1].fn = func() error {
		enrichment.EnrichRedHatScores(ctx, records, logf)
		return nil
	}

	// Step 3: Check CISA KEV
	steps[2].fn = func() error {
		enrichment.EnrichKEV(ctx, records, logf)
		return nil
	}

	// Step 4: Fetch RHSA descriptions
	steps[3].fn = func() error {
		enrichment.EnrichRHSADescriptions(ctx, records, logf)
		return nil
	}

	// Step 5: Scan latest images (only latest, not current — per user request)
	steps[4].fn = func() error {
		enrichment.ScanLatestImages(ctx, records, settings, logf)
		return nil
	}

	// Step 6: Compute SLA deadlines
	steps[5].fn = func() error {
		ComputeSLADeadlines(records)
		logf("  Computed SLA deadlines")
		return nil
	}

	// Step 7: Detect changes from previous data
	steps[6].fn = func() error {
		if isRegen {
			oldRecords, err := r.store.GetRecords(ctx, reportID)
			if err == nil && len(oldRecords) > 0 {
				updates := DetectChanges(oldRecords, records)
				if len(updates) > 0 {
					logf("  Detected %d field changes", len(updates))
					r.store.SaveUpdates(ctx, reportID, updates)
				}
			}
		}
		return nil
	}

	for i, step := range steps {
		select {
		case <-ctx.Done():
			logf("Pipeline aborted")
			r.store.UpdateReportStatus(context.Background(), reportID, cveatypes.StatusError, "", "Aborted by user")
			return
		default:
		}

		stepLabel := fmt.Sprintf("Step %d/%d: %s", i+1, len(steps), step.name)
		logf(stepLabel)
		r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusRunning, step.name, "")

		if err := step.fn(); err != nil {
			logf("ERROR at step %d: %v", i+1, err)
			r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusError, step.name, err.Error())
			return
		}
	}

	// Save final records
	if err := r.store.ReplaceRecords(ctx, reportID, records); err != nil {
		logf("ERROR saving records: %v", err)
		r.store.UpdateReportStatus(ctx, reportID, cveatypes.StatusError, "Saving results", err.Error())
		return
	}

	if err := r.store.CompleteReport(ctx, reportID, len(records), isRegen); err != nil {
		logf("ERROR completing report: %v", err)
		return
	}

	logf("Pipeline complete: %d records", len(records))
}
