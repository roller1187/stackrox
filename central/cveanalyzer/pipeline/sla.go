package pipeline

import (
	"fmt"
	"strings"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

var slaTierWindows = map[string]int{
	"Critical/High": 30,
	"Moderate":      90,
	"Low":           180,
}

func slaWindow(tier string) int {
	if w, ok := slaTierWindows[tier]; ok {
		return w
	}
	return 180
}

func classifySLATier(severity, rhSeverity string) string {
	sev := strings.ToUpper(rhSeverity)
	if sev == "" {
		sev = strings.ToUpper(severity)
	}
	switch sev {
	case "CRITICAL", "IMPORTANT", "HIGH":
		return "Critical/High"
	case "MODERATE", "MEDIUM":
		return "Moderate"
	default:
		return "Low"
	}
}

// ComputeSLADeadlines sets SLA tier and deadline on each record based on severity and discovery date.
func ComputeSLADeadlines(records []cveatypes.CVERecord) {
	for i := range records {
		r := &records[i]
		tier := classifySLATier(r.Severity, r.RHSeverity)
		r.SLATier = tier

		discovered := r.Discovered
		if discovered == "" {
			continue
		}

		var t time.Time
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			"2006-01-02",
		} {
			if parsed, err := time.Parse(layout, discovered); err == nil {
				t = parsed
				break
			}
		}
		if t.IsZero() {
			continue
		}

		// Use KEV due date if available, otherwise compute from SLA window
		if r.KEVDueDate != "" {
			r.SLADeadline = r.KEVDueDate
		} else {
			window := slaWindow(tier)
			deadline := t.AddDate(0, 0, window)
			r.SLADeadline = deadline.Format("2006-01-02")
		}
	}
}

// DetectChanges compares old and new records and returns update entries for changed fields.
func DetectChanges(oldRecords, newRecords []cveatypes.CVERecord) map[string]cveatypes.UpdateEntry {
	oldMap := make(map[string]*cveatypes.CVERecord, len(oldRecords))
	for i := range oldRecords {
		oldMap[oldRecords[i].Key] = &oldRecords[i]
	}

	trackedFields := []struct {
		name string
		get  func(*cveatypes.CVERecord) string
	}{
		{"priority", func(r *cveatypes.CVERecord) string { return r.Priority }},
		{"action", func(r *cveatypes.CVERecord) string { return r.Action }},
		{"cvss", func(r *cveatypes.CVERecord) string { return r.CVSS }},
		{"rh_cvss", func(r *cveatypes.CVERecord) string { return r.RHCVSS }},
		{"epss_pct", func(r *cveatypes.CVERecord) string { return r.EpssPct }},
		{"fix_status", func(r *cveatypes.CVERecord) string { return r.FixStatus }},
		{"severity", func(r *cveatypes.CVERecord) string { return r.Severity }},
		{"rh_severity", func(r *cveatypes.CVERecord) string { return r.RHSeverity }},
		{"kev_date_added", func(r *cveatypes.CVERecord) string { return r.KEVDateAdded }},
		{"component_version", func(r *cveatypes.CVERecord) string { return r.ComponentVersion }},
		{"fixed_in", func(r *cveatypes.CVERecord) string { return r.FixedIn }},
	}

	updates := make(map[string]cveatypes.UpdateEntry)

	for i := range newRecords {
		newRec := &newRecords[i]
		oldRec, exists := oldMap[newRec.Key]
		if !exists {
			continue
		}

		fields := make(map[string]cveatypes.FieldChange)
		for _, f := range trackedFields {
			oldVal := f.get(oldRec)
			newVal := f.get(newRec)
			if oldVal != newVal && (oldVal != "" || newVal != "") {
				fields[f.name] = cveatypes.FieldChange{Old: oldVal, New: newVal}
			}
		}

		if len(fields) > 0 {
			updates[newRec.Key] = cveatypes.UpdateEntry{
				Fields:       fields,
				DetectedAt:   fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
				Acknowledged: false,
			}
		}
	}

	return updates
}
